#include "Instruction.hpp"

Instruction::Instruction() {
	enum InstructionType : uint32_t{
		kill,
		restart,
		keydump,
		runshell
	};

	Instruction::cmd = "C:\Windows\System32\cmd.exe";
	Instruction::pws = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
	Instruction::pws32 = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe";
};
