#include "IncludeMe.hpp"
#include <iostream>

bool PNet::Network::Initialize() {
    WSADATA ws;
    int result;
    result = WSAStartup(MAKEWORD(2, 2), &ws);
    if (result!=0) {
        std::cerr << "Failed to start winsock API. " << std::endl; 
        return false;
    };

    if (LOBYTE(ws.wVersion) != 2 || HIBYTE(ws.wVersion) != 2) {
        std::cerr << "Could not find a usable version of the winsock api dll. " << std::endl;
        return false;
    }

    return true;
}

void PNet::Network::ShutDown() {
    WSACleanup();
}
