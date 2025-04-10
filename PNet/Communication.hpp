#pragma once
#include "IncludeMe.hpp"
#include <thread>
#include <mutex>
#include <memory>

class Communication  {
public:
	Communication();
	virtual ~Communication() = default;

	virtual bool TextThread(std::uint16_t index=NULL, std::string a = NULL) =0 ;
	virtual bool SetJThread(std::jthread&& jthread) = 0;
	virtual bool IsCommunicationOpen() = 0;

	// extremely retarded, damages incapsulation as private members are exposed
	virtual  std::mutex& GetMutex() = 0;
	virtual  std::jthread& GetJThread() = 0;
//	virtual  std::jthread& SetJThreadFunWay() = 0;
};


class ServerCommunication : public Communication {

public:    
	ServerCommunication();
	ServerCommunication(Server& server);
	ServerCommunication(Server* server);

	~ServerCommunication() override;
	void Text(uint16_t index);
	bool TextThread(std::uint16_t index=NULL,std::string a = NULL ) override;
	bool SetJThread(std::jthread&& jthread) override ;
	bool IsCommunicationOpen() override;
	// ListCommunications   
	// EnqueueMessage
	std::mutex& GetMutex()override;
	std::jthread& GetJThread()override;
	std::mutex serverCommunicationMutex;
	std::jthread serverCommunicationJThread;
	std::shared_ptr<Server> pServerCommunication;
	std::atomic<bool> ServerCommunnicationOpen = false;

};


class ClientCommunication : public Communication {
public:
	std::shared_ptr<ClientCommunication> pCC;
	ClientCommunication();
	ClientCommunication(Client& client);
	~ClientCommunication() override;
	bool TextThread(std::uint16_t index=NULL, std::string msg=NULL) override;
	bool SetJThread(std::jthread&& jthread) override;
	bool IsCommunicationOpen() override;
	void T();
	std::deque<std::shared_ptr<Packet>> queueIn;
	std::mutex& GetMutex() override ;
	std::mutex clientCommunicationMutex;
	std::jthread& GetJThread() override;
	std::jthread clientCommunicationJThread;
	std::shared_ptr<Client> pClient;
	bool clientCommunnicationOpen = false;

};

