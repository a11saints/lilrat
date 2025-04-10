#pragma once
#include <Windows.h>


#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>

class Util {
public:
    Util();
    PPEB GetPEB();
    FARPROC GetFunctionAddressFromExport(PVOID hModule, const char* funcName);
    PVOID FindBase(std::wstring dll);
};


