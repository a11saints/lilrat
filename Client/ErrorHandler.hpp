#pragma once
#include <iostream>
#include <vector>

class ErrorHandler
{
public:
	ErrorHandler();
	~ErrorHandler();

	static void ErrorProcessor(std::string ErrorDesription, int ExceptionType);
	static void ErrorRecorder();
	static int errorNumber;
	static int errorCode;
	static std::vector < std::pair<std::string, int>> errorArray;

};

