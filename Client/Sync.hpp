#pragma once
#include <mutex>
#include <thread>
#include <Windows.h>
#include <vector>

class  Sync {
public:
	Sync();
	~Sync();
	 std::mutex cmdMutex;
	 std::mutex commMutex;
	 HANDLE clientBufferFilled;
	 HANDLE cmdInstructionObtained;
	 HANDLE shellOutputReceived;
	 HANDLE eConnRecv;
	 HANDLE eConnSend;
	 std::vector<HANDLE>eConnVector;
};

