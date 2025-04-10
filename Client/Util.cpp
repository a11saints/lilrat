#include "Utils.hpp"


Util::Util(){
}

PPEB Util::GetPEB() {
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}


PVOID Util::FindBase(std::wstring dll) {
    PPEB peb = nullptr;

#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(
            entry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        std::wstring baseName(
            moduleEntry->FullDllName.Buffer,
            moduleEntry->FullDllName.Length / sizeof(WCHAR)
        );

        if (baseName.find(dll) != std::string::npos) {
            return moduleEntry->DllBase;
        }
        entry = entry->Flink;
    }
    return nullptr;
}

FARPROC Util::GetFunctionAddressFromExport(PVOID hModule, const char* funcName) {
    if (!hModule || !funcName) return nullptr;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportTable->AddressOfNames);
    WORD* ordinalTable = (WORD*)((BYTE*)hModule + exportTable->AddressOfNameOrdinals);
    DWORD* functionTable = (DWORD*)((BYTE*)hModule + exportTable->AddressOfFunctions);

    for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + nameRVAs[i]);
        if (strcmp(name, funcName) == 0) {
            DWORD funcRVA = functionTable[ordinalTable[i]];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }
    return nullptr;
}

//extern PVOID FindNtdllBase();

