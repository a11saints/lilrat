#pragma once
#include "Socket.hpp"
#include "PacketManager.hpp"
#include "FileTransferHandler.hpp"
namespace PNet {

	class TCPConnection {
	public:
		TCPConnection(Socket socket, IPEndpoint endpoint);
		TCPConnection() :socket(Socket()) {};
		void Close();
		std::string ToString();
		Socket socket;
		PacketManager pm_incoming; 
		PacketManager pm_outgoing;
		char buffer[PNet::g_MaxPacketSize];
		FileTransferHandler filetransferhandler;

	private:
		IPEndpoint endpoint;
		std::string stringRepresentation = "";
		
	};
}