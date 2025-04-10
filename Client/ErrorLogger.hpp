#pragma once
#include <string>

class ErrorLogger {
public:
	ErrorLogger();
	~ErrorLogger();
	void ShowErrorMessage(std::string em);
private:
	int errorCode;
	std::string erb = "[-]";
	std::string evb= "[+]";
	std::string q= ": ";
	std::string nl= "\n";

};
