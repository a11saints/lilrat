#pragma once
#include "Utils.hpp"

class VEHDumper {
public:
    VEHDumper();
    VEHDumper(std::shared_ptr<Util>);

    void LoadNtdll();
    int ReloadNtDll();
    PVOID FindNtdllBase();
    PVOID GetLdrpVectorHandlerList();
    ULONG GetProcessCookie();
    long DumpVEH();
    int TestVEH(int v);
    void RemoveAllVEHs();
    void RegisterVEHs();
    static LONG CALLBACK VEH1(PEXCEPTION_POINTERS pExceptionInfo);
    static LONG WINAPI VEH2(PEXCEPTION_POINTERS pExceptionPointers);

    FARPROC ntquery;
    FARPROC ntalloc;
    LPVOID exceptionHandler;
     PVOID hNtdll;
    std::vector<LPVOID> VEHs;
};


