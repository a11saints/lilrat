#pragma once
#include "Utils.hpp"

class ETWC3 {

public:
    ETWC3() ;
    ETWC3(std::shared_ptr<Util>) ;
    FARPROC ntquery;
    FARPROC ntProtect;
    FARPROC zwWrite;
    FARPROC etwEvent;
    FARPROC ntCurrProc;
    PVOID hNtdll;
    PPEB peb;
    PVOID FindNtdllBase();
    void RetETW();
};


