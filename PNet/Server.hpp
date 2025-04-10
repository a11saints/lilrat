#pragma once
#include "TCPConnection.hpp"

using namespace PNet;

namespace PNet {
	class Server {
	public:
		bool Initialize(IPEndpoint ip);
		void Frame();
		std::vector<TCPConnection>& GetConnectionsList();
	
	protected:
		virtual void OnConnect(TCPConnection& newConnection);
		virtual void OnDisconnect(TCPConnection& lostConnection, std::string reason);
		void CloseConnection(int connectionIndex, std::string reason);
		virtual void CreatePacket(TCPConnection& newConnection, std::string message);
		virtual bool ProcessPacket(std::shared_ptr <Packet> packet);
		Socket listeningSocket;
		std::vector<TCPConnection> connections;
		std::vector <WSAPOLLFD> master_fd;
		std::vector <WSAPOLLFD> use_fd;
	};
}

