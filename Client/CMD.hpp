#pragma once
#include <PNet/IncludeMe.hpp>
#include "CMD.hpp"

class CMD {
public:
	CMD();
	~CMD();
public:
	bool Spawn();
	void WritePipe(std::string c);
	std::string ReadPipe();
	int Session();
	bool Start();

	bool cmdOpen = false; //shellOpen

	std::shared_ptr<CMD> cmdPtr; // pShell

	std::jthread cmdJthread; // shellJThread

	std::deque<std::string> commandQueueIn;
	std::deque<std::string> commandQueueOut;

	HANDLE child_IN_READ = NULL;
	HANDLE child_IN_WRITE = NULL;
	HANDLE child_OUT_READ = NULL;
	HANDLE child_OUT_WRITE = NULL;
};


