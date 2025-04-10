#pragma once
#include "TCPConnection.hpp"

namespace PNet
{
	class Client {
	public:
		Client();
		virtual ~Client();
		bool Connect(IPEndpoint ip);
		bool IsConnected();
		bool Frame();
		std::unique_ptr<Client> clientUPtr;
		std::string clientBuffer;
		TCPConnection connection;
	protected:
		virtual bool ProcessPacket(std::shared_ptr<Packet> packet);
		virtual void OnConnect();
		virtual void OnConnectFail();
		virtual void OnDisconnect(std::string reason);
		void CloseConnection(std::string reason);
		
	private:
		bool isConnected = false;
		WSAPOLLFD master_fd;
		WSAPOLLFD use_fd;
	};
}