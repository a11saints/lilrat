#pragma once
#include "IncludeMe.hpp"
class Instruction {
public:

	Instruction() ;
	enum class InstructionType;
private:

	std::string pws;
	std::string cmd;
	std::string pws32;
};