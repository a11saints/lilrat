#include "MyServer.hpp"
#include <iostream>

using namespace PNet;

int main() {
	if (Network::Initialize()) {
		MyServer server;

		ServerCommunication sc(server);
		
		if (server.Initialize(IPEndpoint("127.0.0.1", 6112))) {
			sc.TextThread(0,"");
			while (true) {
				server.Frame();
			
			}
		}
	}

	Network::ShutDown();
	system("pause");
	return 0;
}
