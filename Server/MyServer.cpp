#include "MyServer.hpp"
#include <iostream>


void MyServer::CreatePacket(TCPConnection & newConnection, std::string message ) {
	 std::shared_ptr<Packet> packet = std::make_shared<Packet>(PacketType::PT_ChatMessage);
	 *packet << message;
	newConnection.pm_outgoing.Append(packet);
}



void MyServer::OnConnect(TCPConnection& newConnection) {
	std::shared_ptr<Packet> welcomeMessagePacket = std::make_shared<Packet>(PacketType::PT_ChatMessage);
	*welcomeMessagePacket << std::string("Welcome!");
	newConnection.pm_outgoing.Append(welcomeMessagePacket);

	std::cout << newConnection.ToString() << "\n[+] New connection accpeted";
	std::shared_ptr<Packet> newUserMessagePacket = std::make_shared<Packet>(PacketType::PT_ChatMessage);
	*newUserMessagePacket << std::string("\n[+] New user connected!");

}

void MyServer::OnDisconnect(TCPConnection& lostConnection, std::string reason) {

	std::cout << "\n[" << reason << " ] Connection lost: " << lostConnection.ToString() << "." ;

	std::shared_ptr<Packet> connectionLostPacket = std::make_shared<Packet>(PacketType::PT_ChatMessage);
	*connectionLostPacket << std::string("\n[+] User disconnected!");

	for (auto& connection : connections) {
		if (&connection == &lostConnection)
			continue;
		connection.pm_outgoing.Append(connectionLostPacket);
	}
}

bool MyServer::ProcessPacket(std::shared_ptr <Packet> packet) {

	if (packet->buffer.size() == 6) { return true; }
	
	switch (packet->GetPacketType())
	{
		case PacketType::PT_ChatMessage:
		{
			std::string chatmessage;
			*packet >> chatmessage;
			std::cout << "\n[+] Chat Message: " << chatmessage ;
			break;
		}

		case PacketType::PT_IntegerArray:
		{
			uint32_t arraySize = 0;
			*packet >> arraySize;
			std::cout << "Array size: " << arraySize << std::endl;

			for (uint32_t i = 0; i < arraySize; i++) {
				uint32_t element = 0;
				*packet >> element;
				std::cout << "Element[" << i << "] " << element << std::endl;
			}
			break;
		}
		default:
			std::cout << "Unrecognized packet type: " << packet->GetPacketType() << std::endl;
			return false;
	}
	return true;
}

