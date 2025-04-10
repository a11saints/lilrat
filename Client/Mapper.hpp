#pragma once



#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#pragma comment (lib, "advapi32")
#pragma comment(lib, "ntdll")
class Mapper {
public:
	
	Mapper();
	~Mapper();
	int InjectView( unsigned char* shellcode, SIZE_T shellcode_length,int pid);
	int FindTarget(WCHAR* process_name);
	int Inject(int mode);
};


