#include "Sync.hpp"
#include <Windows.h>

Sync::Sync() {
	
	cmdInstructionObtained = CreateEventW(NULL, TRUE, FALSE, NULL);
	clientBufferFilled = CreateEventW(NULL, TRUE, FALSE, NULL);
	shellOutputReceived = CreateEventW(NULL, TRUE, FALSE, NULL);
	
	eConnSend = CreateEventW(NULL, TRUE, FALSE, NULL);
	eConnRecv = CreateEventW(NULL, TRUE, FALSE, NULL);

	eConnVector.push_back(eConnSend);
	eConnVector.push_back(eConnRecv);
};

Sync::~Sync() {
	CloseHandle(cmdInstructionObtained); // 
	CloseHandle(clientBufferFilled);
	CloseHandle(shellOutputReceived);
	CloseHandle(eConnSend);
	CloseHandle(eConnRecv);
};

