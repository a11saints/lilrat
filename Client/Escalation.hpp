#pragma once
#include <windows.h>
#include <iostream>
#include "LazyImporter.hpp"
#include <TlHelp32.h>
#include <sddl.h>
#include <vector>
#include <string>

class TokenThief {
public:
	TokenThief();
	bool IsSystemSid(PSID sid);
	std::vector<std::wstring> GetTokenPrivileges(HANDLE hToken);
	void EnablePrivileges();
	int ParseProcesses();
	void TokenSession();
	HANDLE hToken;
	DWORD sessionId;
	HANDLE duplicateTokenPrimaryHandle = NULL;
	HANDLE duplicateTokenImpersonationHandle = NULL;

	int Escalate(HANDLE& token,int m);
};