#include "ErrorLogger.hpp"
#include <iostream>
#include <Windows.h>

ErrorLogger::ErrorLogger() {

}
ErrorLogger::~ErrorLogger() {

}

void ErrorLogger::ShowErrorMessage(std::string em) {
	int ec = GetLastError();
	std::cout << erb << em << q << ec << nl;
}
