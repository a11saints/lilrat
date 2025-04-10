#include "ErrorHandler.hpp"

ErrorHandler::ErrorHandler() {
	static int errorNumber = 0;
	static int errorCode = 0;

}

void ErrorHandler::ErrorRecorder() {

	//ErrorHandler::errorCode = GetLastError();
	//errorNumber++;
	//char*tmp = strerror(errorCode);
	//std::string errorName = tmp;
	//std::pair<std::string, int> errorRecord;
	//errorRecord.first = errorName;
	//errorRecord.second = errorNumber;
	//errorArray.push_back(errorRecord);

}