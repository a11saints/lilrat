#include "LazyImporter.hpp"
#include "DumpVEHs.hpp"

/*
    TODO:
    1. wrap functions to DumpVEHs and UnhookAPIs classes
    2. substitute all apis with LazyImporter macros.
*/

FARPROC ntquery;
LPVOID exceptionHandler;
PVOID hNtdll;
std::vector<LPVOID> VEHs;

typedef NTSTATUS(*PNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef struct _LDRP_VECTOR_HANDLER_LIST {
    PSRWLOCK LdrpVehLock;
    LIST_ENTRY LdrpVehList;
    PSRWLOCK LdrpVchLock;
    LIST_ENTRY LdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, * PLDRP_VECTOR_HANDLER_LIST;

typedef struct _VECTOR_HANDLER_ENTRY {
    LIST_ENTRY ListEntry;
    PLONG64 pRefCount; // ProcessHeap allocated, initialized with 1
    DWORD unk_0; // always 0
    DWORD pad_0;
    PVOID EncodedHandler;
} VECTOR_HANDLER_ENTRY, * PVECTOR_HANDLER_ENTRY;



VEHDumper::VEHDumper() {
}

VEHDumper::VEHDumper( std::shared_ptr<Util> u) {
    hNtdll = FindNtdllBase();
    ntquery = u->GetFunctionAddressFromExport(hNtdll, "NtQueryInformationProcess") ;
    ntalloc= u->GetFunctionAddressFromExport(hNtdll, "NtAllocateVirtualMemory") ;

}
    

LONG CALLBACK VEHDumper::VEH1(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        printf("Guard Page Access Detected!\n");
        // Here you can add logic to log the violation, analyze the access pattern,
        // or take any other appropriate action based on your EDR's requirements.
        // Optional: Restore the guard page here if you want continuous monitoring
        // Continue execution after handling the exception
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI VEHDumper::VEH2(PEXCEPTION_POINTERS pExceptionPointers) {
    if (pExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        printf("Exception Breakpoint Detected!\n");

        pExceptionPointers->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH; 
}

void VEHDumper::LoadNtdll() {
    char ntdll[] = "ntdll.dll";
    HMODULE module = LI_FN(LoadLibraryA)(ntdll);
    ntquery = LI_FN(GetProcAddress)(module, "NtQueryInformationProcess");
}

PVOID VEHDumper::FindNtdllBase() {
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
        PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD (
            entry, 
            LDR_DATA_TABLE_ENTRY, 
            InMemoryOrderLinks
        );

        std::wstring baseName(
            moduleEntry->FullDllName.Buffer,
            moduleEntry->FullDllName.Length / sizeof(WCHAR)
        );

        if (baseName.find(L"ntdll.dll") != std::string::npos) {
            return moduleEntry->DllBase;
        }
        entry = entry->Flink;
    }
    return nullptr;
}

PVOID VEHDumper::GetLdrpVectorHandlerList() {
    // Byte pattern for LdrpVectorHandlerList for windows 10 is: 48 83 EC 20 44 8B ? ? 8D ? ? ? ? ? 48 8B E9
    // Pattern to search for: 0x4883EC20448BF24C8D254EEB0F00 (last 4 bytes are the offset)
    const BYTE pattern[] = { 0x48, 0x83, 0xEC, 0x20, 0x44, 0x8B, 0xF2, 0x4C, 0x8D, 0x25 };
    const size_t patternLength = sizeof(pattern);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (strncmp((const char*)textSection->Name, ".text", 5) == 0) {
            break;
        }
        textSection++;
    }
    BYTE* textSectionStart = (BYTE*)hNtdll + textSection->VirtualAddress;
    DWORD textSectionSize = textSection->Misc.VirtualSize;
    for (DWORD i = 0; i < textSectionSize - patternLength; i++) {
        if (memcmp(textSectionStart + i, pattern, patternLength) == 0) {
            int32_t offset = *(int32_t*)(textSectionStart + i + patternLength);
            BYTE* instruction_after_offset = textSectionStart + i + patternLength + 4;
            BYTE* ldrpVehList = instruction_after_offset + offset;
            return ldrpVehList;
        }
    }
    return NULL;
}


ULONG VEHDumper::GetProcessCookie() {
    // unsure if reinterpet should be used, but works
    PNtQueryInformationProcess pNtQueryInformationProcess = reinterpret_cast<PNtQueryInformationProcess>(ntquery);
    ULONG ulCookie = 0;
    NTSTATUS result = pNtQueryInformationProcess((HANDLE)-1, (PROCESSINFOCLASS) 0x24 /*ProcessCookie*/, &ulCookie, sizeof(ULONG), NULL);
    if (!NT_SUCCESS(result)) return 0;
    return ulCookie;
}



// tested on 23H2
long VEHDumper::DumpVEH() {
    _LDRP_VECTOR_HANDLER_LIST* pLdrpVectorHandlerList = static_cast<_LDRP_VECTOR_HANDLER_LIST*>(GetLdrpVectorHandlerList());
    LIST_ENTRY* pListHead = &pLdrpVectorHandlerList->LdrpVehList;
    std::cout << "\n[+] VEH List head address: " << pListHead ;
    for (LIST_ENTRY* pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink) {
        PVECTOR_HANDLER_ENTRY pEntry = CONTAINING_RECORD(pListEntry, VECTOR_HANDLER_ENTRY, ListEntry);
        if (pEntry == NULL ) return 0;
        LPVOID pExceptionHandler = DecodePointer(pEntry->EncodedHandler);
        std::cout << "\n[+] Exception handler address: " << pExceptionHandler;
        VEHs.push_back(pExceptionHandler);
    }
    return 0;
}


int VEHDumper::TestVEH(int VEHNumber) {
    SYSTEM_INFO si;
    GetSystemInfo(&si); 
    LPVOID pMemory = VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT, PAGE_READWRITE);
    if (pMemory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    DWORD oldProtect;
    if (!VirtualProtect(pMemory, si.dwPageSize, PAGE_GUARD | PAGE_READWRITE, &oldProtect)) {
        printf("Failed to set guard page\n");
        VirtualFree(pMemory, 0, MEM_RELEASE); 
        return 1;
    }

    PVOID hVEH1 = AddVectoredExceptionHandler(1, VEH1);
    if (hVEH1 == NULL) {
        printf("Failed to add Vectored Exception Handler\n");
        VirtualFree(pMemory, 0, MEM_RELEASE); 
        return 1;
    }

    PVOID hVEH2 = AddVectoredExceptionHandler(1, VEH2);
    if (hVEH2 == NULL) {
        printf("Failed to add Vectored Exception Handler\n");
        VirtualFree(pMemory, 0, MEM_RELEASE); 
        return 1;
    }

    switch (VEHNumber) {
        case 1:
            //raise veh1
             *(static_cast<char*>(pMemory)) = 'a';
             VirtualFree(pMemory, 0, MEM_RELEASE);
             break;
    
        case 2:
            //raise veh2
            DebugBreak();
            break;
    }
    return 0;
    
}


void VEHDumper::RemoveAllVEHs() {

    for (auto veh : VEHs) {
        RemoveVectoredExceptionHandler(veh);
        std::cout << "\n[+] Removed VEH at: " <<veh;
    }
}

void VEHDumper::RegisterVEHs()
{
}


int VEHDumper::ReloadNtDll() {

    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
            std::cout << "\n[+] Ntdll reloaded";

        }
    }

    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);
    return 0;
}

//int main() {
//    VEHDumper vehd(std::make_shared<Util>());
//    vehd.GetProcessCookie();
//
//    vehd.TestVEH(1);
//    vehd.TestVEH(2);
//
//    vehd.DumpVEH();
//    vehd.RemoveAllVEHs();
//    return 0;
//}
