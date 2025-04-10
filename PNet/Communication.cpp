#include "IncludeMe.hpp"
#include <iostream>
#include <thread>
#include <mutex> 
#include <functional>

Communication::Communication() {}

ServerCommunication::ServerCommunication() {
}


ServerCommunication::~ServerCommunication() {
}


ServerCommunication::ServerCommunication( Server& s ) {
	pServerCommunication = std::shared_ptr<Server>(&s);
	if (pServerCommunication != nullptr) {
		ServerCommunnicationOpen = true;
	}
}

ServerCommunication::ServerCommunication(Server* s) {
	pServerCommunication = std::shared_ptr<Server>(s);
	if (pServerCommunication != nullptr) {
		ServerCommunnicationOpen = true;
	}
}

void ServerCommunication::Text(std::uint16_t communicationIndex) {
	while (IsCommunicationOpen()) {
		GetMutex().lock();
		std::string opt, data;
		std::cout << "\n[?] Chose option: ";
		std::getline(std::cin, opt);
		std::cout << "\n[?] Enter data: ";
		std::getline(std::cin, data);
		std::shared_ptr<Packet> temp;

		if (opt == "cmd") {
			std::shared_ptr<Packet> packet = std::make_shared<Packet>(PacketType::PT_Shell);
			*packet << data;
			temp = packet;
		}
		else if (opt == "command") {
			std::shared_ptr<Packet> packet = std::make_shared<Packet>(PacketType::PT_Command);
			*packet << data;
			temp = packet;
		}
		else {
			std::shared_ptr<Packet> packet = std::make_shared<Packet>(PacketType::PT_ChatMessage);
			*packet << data;
			temp = packet;
		}

		pServerCommunication->GetConnectionsList()[communicationIndex].pm_outgoing.Append(temp);
		auto& connList = pServerCommunication->GetConnectionsList();

		GetMutex().unlock();
	}
}

bool ServerCommunication::TextThread(std::uint16_t communicationIndex,std::string msg){	
	std::function<void(std::uint16_t)> fnText = std::bind(&ServerCommunication::Text, this, std::placeholders::_1);
	std::jthread j1(fnText,communicationIndex); //std invoke error no matching overloaded functio found
	SetJThread(std::move(j1));
	return 0;
}
bool ServerCommunication::SetJThread(std::jthread&& jthread) {
	serverCommunicationJThread = std::move(jthread);
	return true;
}

bool ServerCommunication::IsCommunicationOpen() {
	return ServerCommunnicationOpen;
}

std::mutex& ServerCommunication::GetMutex() {
	return serverCommunicationMutex;
}
std::jthread& ServerCommunication::GetJThread() {
	return serverCommunicationJThread;
}


ClientCommunication::ClientCommunication(Client & client) {
	pClient = std::shared_ptr<Client>(&client);
	pCC = std::shared_ptr<ClientCommunication>(this);
	clientCommunnicationOpen = true;
	TextThread(NULL,"");
}

ClientCommunication::~ClientCommunication() {
}

void  ClientCommunication::T() {
	while (IsCommunicationOpen()) {
		GetMutex().lock();
		//std::shared_ptr<Packet> packet = std::make_shared<Packet>(PacketType::PT_ChatMessage);
		//*packet << msg;
		while (!queueIn.empty()) {
			pClient->connection.pm_outgoing.Append(queueIn.front());
			queueIn.pop_front();
		}
		GetMutex().unlock();
	}
}

bool ClientCommunication::TextThread(std::uint16_t communicationIndex ,std::string msg ) {
	std::jthread j1(&ClientCommunication::T, std::ref(*pCC));
	if (j1.joinable()) {
		j1.detach();
		//SetJThread(std::move(j1));
	}
	return 0;
}


bool ClientCommunication::SetJThread(std::jthread&& jthread) {
	clientCommunicationJThread = std::move(jthread);
	return true;
}

bool ClientCommunication::IsCommunicationOpen() {
	return clientCommunnicationOpen;
}

std::mutex& ClientCommunication::GetMutex() {
	return clientCommunicationMutex;
}

std::jthread& ClientCommunication::GetJThread() {
	return clientCommunicationJThread;
}


