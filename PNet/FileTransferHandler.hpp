#pragma once

#include <fstream>
#include <string_view>
#include <string>
#include <array>

class FileTransferHandler {

public:

	bool FindFileWithoutPath(std::wstring path);
	
	std::streampos offset;
	std::string filename;
	std::ifstream readStream;
	std::ofstream writeStream;
	std::array<CHAR,8192>buffer;

};
