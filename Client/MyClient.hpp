#pragma once
#include "CMD.hpp"
#include <PNet/IncludeMe.hpp>

class MyClient : public Client {
public:
	std::shared_ptr<Packet> CreatePacket(std::string data, PacketType packetType);
	std::string ExtractDataFromPacket(std::shared_ptr<Packet> pPacket);
	bool ProcessPacket(std::shared_ptr<Packet> packet) override;
	void SendPacket(std::shared_ptr<Packet> packet);
	void OnConnect() override;
	void Sending();

	std::shared_ptr<ClientCommunication> pClientCommunication;
	std::shared_ptr<MyClient> pMyClient;
	std::shared_ptr<CMD> pShell;

	// void OnConnectFail() override;
	// void OnDisconnect(std::string reason) override;
};

