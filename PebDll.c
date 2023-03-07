#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// crc2: "IsDebuggerPresent"
#define IS_DEBUGGER_PRESENT_CRC32 0x8436f795

// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef struct _LDR_DATA_TABLE_ENTRY_COMPLETED
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//rest is not used
} LDR_DATA_TABLE_ENTRY_COMPLETED, *PLDR_DATA_TABLE_ENTRY_COMPLETED;

unsigned int crc32(unsigned char* data, int size)
{
	unsigned int r = ~0; 
	unsigned char* end = data + size;

	while (data < end)
	{
		r ^= *data++;

		for (int i = 0; i < 8; i++)
		{
			unsigned int t = ~((r & 1) - 1); r = (r >> 1) ^ (0xEDB88320 & t);
		}
	}

	return ~r;
}

/* char* string comparison, return true/false */
int string_cmp(char* str1, char* str2) {
	while (*str2 == *str1 && *str2 != 0) {
		str1++;
		str2++;
	}
	return (*str1 == *str2);
}

/* Case insensitive Wstring compare, cmp must be lowercase. returns true/false */
int wstring_cmp_i(wchar_t *str1, wchar_t *str2) {
	WORD* w_cmp = (WORD*)str1;
	WORD* w_other = (WORD*)str2;
	while (*w_other != 0) {
		WORD lowercase_other = ((*w_other >= 'A' && *w_other <= 'Z')
			? *w_other - 'A' + 'a'
			: *w_other);
		if (*w_cmp != lowercase_other) {
			return 0;
		}
		w_cmp++;
		w_other++;
	}
	return (*w_cmp == 0);
}

void* FindProcAddress(char* module, unsigned int hash) {
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)(((char*)pDosHdr) + pDosHdr->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(module +
		pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Get the arrays based on their RVA in the IMAGE_EXPORT_DIRECTORY struct
	DWORD* namesRvaArray = (DWORD*)(module + exportDir->AddressOfNames);
	DWORD* functionRvaArray = (DWORD*)(module + exportDir->AddressOfFunctions);
	WORD* nameOrdinalsArray = (WORD*)(module + exportDir->AddressOfNameOrdinals);

	for (unsigned int i = 0; i< exportDir->NumberOfFunctions; ++i) {
		char* funcName = module + namesRvaArray[i];
		DWORD exportedRva = functionRvaArray[nameOrdinalsArray[i]];

		if (hash == crc32(funcName, (int)strlen(funcName))) {
			return (void*)(module + exportedRva);
		}
	}

	return NULL;
}

void* PebDllSearch(wchar_t *nameToSearch) 
{
#ifdef _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pLdr = pPEB->Ldr;
	PLIST_ENTRY head = &pLdr->InMemoryOrderModuleList;

	for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
        // We follow InMemoryOrder because entry points to LDR_DATA_TABLE_ENTRY_COMPLETED.InMemoryOrderLinks
        // Remove the size of the first element to get the address of the object
		PLDR_DATA_TABLE_ENTRY_COMPLETED pDataTableEntry = (PLDR_DATA_TABLE_ENTRY_COMPLETED)((char*)entry - sizeof(LIST_ENTRY));

		wchar_t *name = pDataTableEntry->BaseDllName.Buffer;

		if (wstring_cmp_i(name, nameToSearch)) {
			return (PVOID)pDataTableEntry->DllBase;
		}
	}

	return 0;
}

int main()
{
	wchar_t *DllNameToSearch = L"kernel32.dll";

	PVOID dllAddress = PebDllSearch(DllNameToSearch);
	if (dllAddress) {
		printf("Here we go the DLL base address of %ls: %p\n", DllNameToSearch, dllAddress);
	}
	else {
		printf("Address not found\n");
		return -1;
	}

	PVOID procAddress = FindProcAddress(dllAddress, IS_DEBUGGER_PRESENT_CRC32);

	if (procAddress) {
		printf("Function address: %p\n", procAddress);
	}
	else {
		printf("No function found\n");
		return -1;
	}

	BOOL(*isDebuggerPresent)() = procAddress;
	
	printf("%s\n", isDebuggerPresent() ? "Yes" : "No");
}
