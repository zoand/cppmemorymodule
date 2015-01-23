/*
 * Memory DLL loading code
 * Version 0.0.4.1
 *
 * Copyright (c) 2004-2014 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * Updated By RLib
 *   [1/23/2015 ASUS]
 *
 */
#ifndef __GNUC__
// disable warnings about pointer <-> DWORD conversions
#pragma warning( disable : 4311 4312 )
#endif

#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#define DEFAULT_LANGUAGE                    MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
#define GET_HEADER_DICTIONARY(module, idx)	&(module)->headers->OptionalHeader.DataDirectory[idx]

#define ERROR_REPORT(s)                     assert(!""#s)

#include <assert.h>
#include "MemoryModule.h"

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
		{ PAGE_READONLY, PAGE_READWRITE },
	},
	{
		// executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
		{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
	},
};

//-------------------------------------------------------------------------

static void CopySections(const unsigned char *data, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
	for (int i = 0; i < module->headers->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (section->SizeOfRawData == 0)
		{
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			int size = old_headers->OptionalHeader.SectionAlignment;
			if (size > 0) {
				void *dest = VirtualAlloc(module->codeBase + section->VirtualAddress,
													 size,
													 MEM_COMMIT,
													 PAGE_EXECUTE_READWRITE);
				assert(dest != nullptr);
				section->Misc.PhysicalAddress = reinterpret_cast<POINTER_TYPE>(dest);
				memset(dest, 0, size);
			}

			// section is empty
			continue;
		}

		// commit memory block and copy data from dll
		void *dest = VirtualAlloc(module->codeBase + section->VirtualAddress,
											 section->SizeOfRawData,
											 MEM_COMMIT,
											 PAGE_EXECUTE_READWRITE);
		assert(dest != nullptr);
		memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
		section->Misc.PhysicalAddress = static_cast<DWORD>(reinterpret_cast<POINTER_TYPE>(dest));
	}
}

//-------------------------------------------------------------------------

static void FinalizeSections(PMEMORYMODULE module)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
	POINTER_TYPE imageOffset = (module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
#define imageOffset 0
#endif

	// loop through all sections and change access flags
	for (int i = 0; i<module->headers->FileHeader.NumberOfSections; ++i, ++section)
	{
		int executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		int readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
		int writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			// section is not needed any more and can safely be freed
			VirtualFree(reinterpret_cast<LPVOID>(static_cast<POINTER_TYPE>(section->Misc.PhysicalAddress | imageOffset)),
						section->SizeOfRawData, MEM_DECOMMIT | MEM_RELEASE);
			continue;
		}

		// determine protection flags based on characteristics
		int protect = ProtectionFlags[executable][readable][writeable];
		if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			protect |= PAGE_NOCACHE;
		}

		// determine size of region
		DWORD size = section->SizeOfRawData;
		if (size == 0) {
			if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
				size = module->headers->OptionalHeader.SizeOfInitializedData;
			}
			else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
				size = module->headers->OptionalHeader.SizeOfUninitializedData;
			}
		}

		if (size > 0) {
			// change memory access flags
			DWORD oldProtect;
			BOOL _result = VirtualProtect(reinterpret_cast<LPVOID>(static_cast<POINTER_TYPE>(section->Misc.PhysicalAddress | imageOffset)),
										  size, protect, &oldProtect);
			assert(_result != FALSE);
		}
	}
#ifndef _WIN64
#undef imageOffset
#endif
}

//-------------------------------------------------------------------------

static void ExecuteTLS(PMEMORYMODULE module)
{
	unsigned char *codeBase = module->codeBase;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory->VirtualAddress > 0)
	{
		auto tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(codeBase + directory->VirtualAddress);
		auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls->AddressOfCallBacks);
		if (callback != nullptr) {
			while (*callback != nullptr) {
				(*callback)(reinterpret_cast<LPVOID>(codeBase), DLL_PROCESS_ATTACH, NULL);
				++callback;
			}
		}
	}
}

//-------------------------------------------------------------------------

static int PerformBaseRelocation(PMEMORYMODULE module, SIZE_T delta)
{
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (directory->Size <= 0) {
		return 0;
	}

	PIMAGE_BASE_RELOCATION relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(module->codeBase + directory->VirtualAddress);
	for (; relocation->VirtualAddress > 0;)
	{
		unsigned char *dest = module->codeBase + relocation->VirtualAddress;
		unsigned short *relInfo = reinterpret_cast<unsigned short *>(reinterpret_cast<unsigned char *>(relocation) + IMAGE_SIZEOF_BASE_RELOCATION);
		for (int i = 0; i < static_cast<int>((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); ++i, ++relInfo)
		{
			// the upper 4 bits define the type of relocation
			int type = *relInfo >> 12;
			// the lower 12 bits define the offset
			int offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				{
					// change complete 32 bit address
					auto patchAddrHL = reinterpret_cast<LPDWORD>(dest + offset);
					*patchAddrHL += static_cast<DWORD>(delta);
				}
				break;

#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64:
				{
					auto patchAddr64 = reinterpret_cast<PULONGLONG>(dest + offset);
					*patchAddr64 += static_cast<ULONGLONG>(delta);
				}
				break;
#endif

			default:
				assert(!"Unknown relocation");
				type = type;
				break;
			}
		}

		// advance to next relocation block
		relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char *>(relocation) + relocation->SizeOfBlock);
	}

	return 1;
}

//-------------------------------------------------------------------------

static int BuildImportTable(PMEMORYMODULE module)
{
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size <= 0) {
		return 1;
	}

	unsigned char *codeBase = module->codeBase;
	PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(codeBase + directory->VirtualAddress);
	for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; ++importDesc)
	{
		POINTER_TYPE *thunkRef;
		FARPROC *funcRef;
		HCUSTOMMODULE handle = module->loadLibrary(reinterpret_cast<LPCSTR>(codeBase + importDesc->Name),
												   module->userdata);
		if (handle == NULL) {
			ERROR_REPORT(ERROR_MOD_NOT_FOUND);
			return 0;
		}

		auto tmp = reinterpret_cast<HCUSTOMMODULE *>(realloc(module->modules, (module->numModules + 1) * sizeof(HCUSTOMMODULE)));
		if (tmp == NULL) {
			module->freeLibrary(handle, module->userdata);
			ERROR_REPORT(ERROR_OUTOFMEMORY);
			return 0;
		}
		module->modules = tmp;

		module->modules[module->numModules++] = handle;
		if (importDesc->OriginalFirstThunk) {
			thunkRef = reinterpret_cast<POINTER_TYPE *>(codeBase + importDesc->OriginalFirstThunk);
			funcRef = reinterpret_cast<FARPROC *>(codeBase + importDesc->FirstThunk);
		}
		else {
			// no hint table
			thunkRef = reinterpret_cast<POINTER_TYPE *>(codeBase + importDesc->FirstThunk);
			funcRef = reinterpret_cast<FARPROC *>(codeBase + importDesc->FirstThunk);
		}
		for (; *thunkRef; thunkRef++, funcRef++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
				*funcRef = module->getProcAddress(handle, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(*thunkRef)),
												  module->userdata);
			}
			else {
				PIMAGE_IMPORT_BY_NAME thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(codeBase + (*thunkRef));
				*funcRef = module->getProcAddress(handle, reinterpret_cast<LPCSTR>(&thunkData->Name),
												  module->userdata);
			}
			if (*funcRef == 0) {
				module->freeLibrary(handle, module->userdata);
				ERROR_REPORT(ERROR_PROC_NOT_FOUND);
				return 0;
			}
		}
	}

	return 1;
}

//-------------------------------------------------------------------------

static HCUSTOMMODULE _LoadLibrary(LPCSTR filename, void *userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	HMODULE result = LoadLibraryA(filename);
	if (result == NULL) {
		return NULL;
	}

	return reinterpret_cast<HCUSTOMMODULE>(result);
}

//-------------------------------------------------------------------------

static FARPROC _GetProcAddress(HCUSTOMMODULE module, LPCSTR name, void *userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	return reinterpret_cast<FARPROC>(GetProcAddress(reinterpret_cast<HMODULE>(module), name));
}

//-------------------------------------------------------------------------

static void _FreeLibrary(HCUSTOMMODULE module, void *userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	FreeLibrary(reinterpret_cast<HMODULE>(module));
}

//-------------------------------------------------------------------------

HMEMORYMODULE MemoryLoadLibrary(const void *data)
{
	return MemoryLoadLibraryEx(data, _LoadLibrary, _GetProcAddress, _FreeLibrary, NULL);
}

//-------------------------------------------------------------------------

HMEMORYMODULE MemoryLoadLibraryEx(const void *data,
								  CustomLoadLibraryFunc loadLibrary,
								  CustomGetProcAddressFunc getProcAddress,
								  CustomFreeLibraryFunc freeLibrary,
								  void *userdata)
{
	PMEMORYMODULE result;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS old_header;
	unsigned char *code, *headers;
	SIZE_T locationDelta;
	BOOL successfull;

	dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<void *>(data));
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		ERROR_REPORT(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	old_header = reinterpret_cast<PIMAGE_NT_HEADERS>(&reinterpret_cast<unsigned char *>(const_cast<void *>(data))[dos_header->e_lfanew]);
	if (old_header->Signature != IMAGE_NT_SIGNATURE) {
		ERROR_REPORT(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

#ifdef _WIN64
	if (old_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
#else
	if (old_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
#endif
		ERROR_REPORT(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	code = (unsigned char *)VirtualAlloc(reinterpret_cast<LPVOID>(old_header->OptionalHeader.ImageBase),
										 old_header->OptionalHeader.SizeOfImage,
										 MEM_RESERVE | MEM_COMMIT,
										 PAGE_EXECUTE_READWRITE);

	if (code == NULL) {
		// try to allocate memory at arbitrary position
		code = (unsigned char *)VirtualAlloc(NULL,
											 old_header->OptionalHeader.SizeOfImage,
											 MEM_RESERVE | MEM_COMMIT,
											 PAGE_EXECUTE_READWRITE);
		if (code == NULL) {
			ERROR_REPORT(ERROR_OUTOFMEMORY);
			return NULL;
		}
	}

	result = reinterpret_cast<PMEMORYMODULE>(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)));
	if (result == NULL) {
		ERROR_REPORT(ERROR_OUTOFMEMORY);
		VirtualFree(code, 0, MEM_RELEASE);
		return NULL;
	}

	result->codeBase = code;
	result->numModules = 0;
	result->modules = NULL;
	result->initialized = 0;
	result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	result->loadLibrary = loadLibrary;
	result->getProcAddress = getProcAddress;
	result->freeLibrary = freeLibrary;
	result->userdata = userdata;

	// commit memory for headers
	headers = (unsigned char *)VirtualAlloc(code,
											old_header->OptionalHeader.SizeOfHeaders,
											MEM_COMMIT,
											PAGE_READWRITE);

	// copy PE header to code
	memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);
	result->headers = reinterpret_cast<PIMAGE_NT_HEADERS>(&headers[dos_header->e_lfanew]);

	// update position
	result->headers->OptionalHeader.ImageBase = reinterpret_cast<POINTER_TYPE>(code);

	// copy sections from DLL file block to new memory location
	CopySections((const unsigned char *)data, old_header, result);

	// adjust base address of imported data
	locationDelta = reinterpret_cast<SIZE_T>(code - old_header->OptionalHeader.ImageBase);
	if (locationDelta != 0) {
		result->isRelocated = PerformBaseRelocation(result, locationDelta);
	}
	else {
		result->isRelocated = 1;
	}

	// load required dlls and adjust function table of imports
	if (!BuildImportTable(result)) {
		goto error;
	}

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	FinalizeSections(result);

	// TLS callbacks are executed BEFORE the main loading
	ExecuteTLS(result);

	// get entry point of loaded library
	if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
		if (result->isDLL) {
			DllEntryProc DllEntry = (DllEntryProc)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
			// notify library about attaching to process
			successfull = (*DllEntry)(reinterpret_cast<HINSTANCE>(code), DLL_PROCESS_ATTACH, 0);
			if (!successfull) {
				ERROR_REPORT(ERROR_DLL_INIT_FAILED);
				goto error;
			}
			result->initialized = 1;
		}
		else {
			result->exeEntry = (ExeEntryProc)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
		}
	}
	else {
		result->exeEntry = NULL;
	}

	return reinterpret_cast<HMEMORYMODULE>(result);

error:
	// cleanup
	MemoryFreeLibrary(result);
	return NULL;
}

//-------------------------------------------------------------------------
	
FARPROC MemoryGetProcAddress(HMEMORYMODULE module, LPCSTR name)
{
	unsigned char *codeBase = reinterpret_cast<PMEMORYMODULE>(module)->codeBase;
	int idx = -1;
	DWORD i, *nameRef;
	WORD *ordinal;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(reinterpret_cast<PMEMORYMODULE>(module), IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (directory->Size == 0) {
		// no export table found
		ERROR_REPORT(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(codeBase + directory->VirtualAddress);
	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
		// DLL doesn't export anything
		ERROR_REPORT(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	// search function name in list of exported names
	nameRef = (DWORD *)(codeBase + exports->AddressOfNames);
	ordinal = (WORD *)(codeBase + exports->AddressOfNameOrdinals);
	for (i = 0; i<exports->NumberOfNames; i++, nameRef++, ordinal++) {
		if (_stricmp(name, (const char *)(codeBase + (*nameRef))) == 0) {
			idx = *ordinal;
			break;
		}
	}

	if (idx == -1) {
		// exported symbol not found
		ERROR_REPORT(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	if (static_cast<DWORD>(idx) > exports->NumberOfFunctions) {
		// name <-> ordinal number don't match
		ERROR_REPORT(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	// AddressOfFunctions contains the RVAs to the "real" functions
	return reinterpret_cast<FARPROC>(codeBase + (*(DWORD *)(codeBase + exports->AddressOfFunctions + (idx * 4))));
}

//-------------------------------------------------------------------------

void MemoryFreeLibrary(HMEMORYMODULE mod)
{
	int i;
	PMEMORYMODULE module = reinterpret_cast<PMEMORYMODULE>(mod);

	if (module != NULL) {
		if (module->initialized != 0) {
			// notify library about detaching from process
			DllEntryProc DllEntry = (DllEntryProc)(module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
			(*DllEntry)(reinterpret_cast<HINSTANCE>(module->codeBase), DLL_PROCESS_DETACH, 0);
			module->initialized = 0;
		}

		if (module->modules != NULL) {
			// free previously opened libraries
			for (i = 0; i<module->numModules; i++) {
				if (module->modules[i] != NULL) {
					module->freeLibrary(module->modules[i], module->userdata);
				}
			}

			free(module->modules);
		}

		if (module->codeBase != NULL) {
			// release memory of library
			VirtualFree(module->codeBase, 0, MEM_RELEASE);
		}

		HeapFree(GetProcessHeap(), 0, module);
	}
}

//-------------------------------------------------------------------------

int MemoryCallEntryPoint(HMEMORYMODULE mod)
{
	PMEMORYMODULE module = reinterpret_cast<PMEMORYMODULE>(mod);

	if (module == NULL || module->isDLL || module->exeEntry == NULL || !module->isRelocated) {
		return -1;
	}

	return module->exeEntry();
}

//-------------------------------------------------------------------------

HMEMORYRSRC MemoryFindResource(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type)
{
	return MemoryFindResourceEx(module, name, type, DEFAULT_LANGUAGE);
}

//-------------------------------------------------------------------------

static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(void *root, PIMAGE_RESOURCE_DIRECTORY resources, LPCTSTR key)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(resources + 1);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY result = NULL;
	DWORD start;
	DWORD end;
	DWORD middle;

	if (!IS_INTRESOURCE(key) && key[0] == TEXT('#')) {
		// special case: resource id given as string
		TCHAR *endpos = NULL;
#if defined(UNICODE)
		long int tmpkey = static_cast<WORD>(wcstol((TCHAR *)&key[1], &endpos, 10));
#else
		long int tmpkey = static_cast<WORD>(strtol((TCHAR *)&key[1], &endpos, 10));
#endif
		if (tmpkey <= 0xffff && lstrlen(endpos) == 0) {
			key = MAKEINTRESOURCE(tmpkey);
		}
	}

	// entries are stored as ordered list of named entries,
	// followed by an ordered list of id entries - we can do
	// a binary search to find faster...
	if (IS_INTRESOURCE(key)) {
		WORD check = static_cast<WORD>(reinterpret_cast<POINTER_TYPE>(key));
		start = resources->NumberOfNamedEntries;
		end = start + resources->NumberOfIdEntries;

		while (end > start) {
			WORD entryName;
			middle = (start + end) >> 1;
			entryName = static_cast<WORD>(entries[middle].Name);
			if (check < entryName) {
				end = (end != middle ? middle : middle - 1);
			}
			else if (check > entryName) {
				start = (start != middle ? middle : middle + 1);
			}
			else {
				result = &entries[middle];
				break;
			}
		}
	}
	else {
#if !defined(UNICODE)
		char *searchKey = NULL;
		int searchKeyLength = 0;
#endif
		start = 0;
		end = resources->NumberOfIdEntries;
		while (end > start) {
			// resource names are always stored using 16bit characters
			int cmp;
			PIMAGE_RESOURCE_DIR_STRING_U resourceString;
			middle = (start + end) >> 1;
			resourceString = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(((char *)root) + (entries[middle].Name & 0x7FFFFFFF));
#if !defined(UNICODE)
			if (searchKey == NULL || searchKeyLength < resourceString->Length) {
				void *tmp = realloc(searchKey, resourceString->Length);
				if (tmp == NULL) {
					break;
				}

				searchKey = (char *)tmp;
			}
			wcstombs(searchKey, resourceString->NameString, resourceString->Length);
			cmp = strncmp(key, searchKey, resourceString->Length);
#else
			cmp = wcsncmp(key, resourceString->NameString, resourceString->Length);
#endif
			if (cmp < 0) {
				end = (middle != end ? middle : middle - 1);
			}
			else if (cmp > 0) {
				start = (middle != start ? middle : middle + 1);
			}
			else {
				result = &entries[middle];
				break;
			}
		}
#if !defined(UNICODE)
		free(searchKey);
#endif
	}


	return result;
}

//-------------------------------------------------------------------------

HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type, WORD language)
{
	unsigned char *codeBase = reinterpret_cast<PMEMORYMODULE>(module)->codeBase;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(reinterpret_cast<PMEMORYMODULE>(module), IMAGE_DIRECTORY_ENTRY_RESOURCE);
	PIMAGE_RESOURCE_DIRECTORY rootResources;
	PIMAGE_RESOURCE_DIRECTORY nameResources;
	PIMAGE_RESOURCE_DIRECTORY typeResources;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;
	if (directory->Size == 0) {
		// no resource table found
		ERROR_REPORT(ERROR_RESOURCE_DATA_NOT_FOUND);
		return NULL;
	}

	if (language == DEFAULT_LANGUAGE) {
		// use language from current thread
		language = LANGIDFROMLCID(GetThreadLocale());
	}

	// resources are stored as three-level tree
	// - first node is the type
	// - second node is the name
	// - third node is the language
	rootResources = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(codeBase + directory->VirtualAddress);
	foundType = _MemorySearchResourceEntry(rootResources, rootResources, type);
	if (foundType == NULL) {
		ERROR_REPORT(ERROR_RESOURCE_TYPE_NOT_FOUND);
		return NULL;
	}

	typeResources = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(codeBase + directory->VirtualAddress + (foundType->OffsetToData & 0x7fffffff));
	foundName = _MemorySearchResourceEntry(rootResources, typeResources, name);
	if (foundName == NULL) {
		ERROR_REPORT(ERROR_RESOURCE_NAME_NOT_FOUND);
		return NULL;
	}

	nameResources = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(codeBase + directory->VirtualAddress + (foundName->OffsetToData & 0x7fffffff));
	foundLanguage = _MemorySearchResourceEntry(rootResources, nameResources, reinterpret_cast<LPCTSTR>(static_cast<POINTER_TYPE>(language)));
	if (foundLanguage == NULL) {
		// requested language not found, use first available
		if (nameResources->NumberOfIdEntries == 0) {
			ERROR_REPORT(ERROR_RESOURCE_LANG_NOT_FOUND);
			return NULL;
		}

		foundLanguage = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(nameResources + 1);
	}

	return (codeBase + directory->VirtualAddress + (foundLanguage->OffsetToData & 0x7fffffff));
}

//-------------------------------------------------------------------------

DWORD MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource)
{
	UNREFERENCED_PARAMETER(module);
	PIMAGE_RESOURCE_DATA_ENTRY entry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(resource);

	return entry->Size;
}

//-------------------------------------------------------------------------

LPVOID MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource)
{
	unsigned char *codeBase = reinterpret_cast<PMEMORYMODULE>(module)->codeBase;
	PIMAGE_RESOURCE_DATA_ENTRY entry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(resource);

	return codeBase + entry->OffsetToData;
}

//-------------------------------------------------------------------------

int MemoryLoadString(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize)
{
	return MemoryLoadStringEx(module, id, buffer, maxsize, DEFAULT_LANGUAGE);
}

//-------------------------------------------------------------------------

int MemoryLoadStringEx(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize, WORD language)
{
	HMEMORYRSRC resource;
	PIMAGE_RESOURCE_DIR_STRING_U data;
	DWORD size;
	if (maxsize == 0) {
		return 0;
	}

	resource = MemoryFindResourceEx(module, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING, language);
	if (resource == NULL) {
		buffer[0] = 0;
		return 0;
	}

	data = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(MemoryLoadResource(module, resource));
	id = id & 0x0f;
	while (id--) {
		data = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>((((char *)data) + (data->Length + 1) * sizeof(WCHAR)));
	}
	if (data->Length == 0) {
		ERROR_REPORT(ERROR_RESOURCE_NAME_NOT_FOUND);
		buffer[0] = 0;
		return 0;
	}

	size = data->Length;
	if (size >= static_cast<DWORD>(maxsize)) {
		size = maxsize;
	}
	else {
		buffer[size] = 0;
	}
#if defined(UNICODE)
	wcsncpy_s(buffer, maxsize, data->NameString, size);
#else
	wcstombs(buffer, data->NameString, size);
#endif
	return size;
}
