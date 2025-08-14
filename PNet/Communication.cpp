#include "IncludeMe.hpp"
#include <iostream>
#include <thread>
#include <mutex> 
#include <functional>
#include <argparse/argparse.hpp>

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
std::vector<std::string> split(std::string str, std::string delimiter) {

	std::vector<std::string> v;
	if (!str.empty()) {
		int start = 0;
		do {
			// Find the index of occurrence
			int idx = str.find(delimiter, start);
			if (idx == std::string::npos) {
				break;
			}

			// If found add the substring till that
			// occurrence in the vector
			int length = idx - start;
			v.push_back(str.substr(start, length));
			start += (length + delimiter.size());
		} while (true);
		v.push_back(str.substr(start));
	}

	return v;
}


// Parse from single string (split into tokens)


void ServerCommunication::Text(std::uint16_t communicationIndex) {
	while (IsCommunicationOpen()) {
		GetMutex().lock();
		std::string commandline,data;
		std::vector<std::string> args;
		std::getline(std::cin, data);

		commandline = GetCommandLineA();

		args = split(data, " ");
		auto v = [&]()->auto {std::vector<std::string>x{ commandline }; for (auto i : args) { x.push_back(i); }; return x; };

		argparse::ArgumentParser program("vector_parser");
		program.add_argument("-c", "--commandline").help("Specify either 'cmd' or 'pws'").choices("cmd", "pws");
		program.add_argument("-t", "--terminate").help("Specify either 0 or 1").choices(0, 1).scan<'i', int>();
		program.add_argument("-h", "--host").help("Specify any number").scan<'i', int>();
		program.add_argument("strings").remaining().default_value(std::string{});

		try {
			program.parse_args(v());
		}
		catch (const std::runtime_error& err) {
			std::cerr << err.what() << std::endl;
			std::cerr << program;
			return ;
		}
	

		std::shared_ptr<Packet> packet,temp;

		if (program.is_used("--commandline")) {
			auto c = program.get<std::string>("--commandline");
			std::cout << "Shell: " << c << "\n";
			 packet = std::make_shared<Packet>(PacketType::PT_Shell);
			*packet << c;
			session = true;
		}
		else if (program.is_used("--terminate")) {
			auto t = program.get<int>("--terminate");
			std::cout << "Terminate: " << t << "\n";
			 packet = std::make_shared<Packet>(PacketType::PT_Command);
			*packet << "exit";
		}
		else if (program.is_used("--host")) {
			auto h= program.get<int>("--host");
			communicationIndex = h;
			std::cout << "Host: " << h << "\n";
		}
		else {
			auto strings = program.get<std::string>("strings"); // change to std::vector<std::stirng>
			 packet = std::make_shared<Packet>(session? PacketType::PT_Command : PacketType::PT_ChatMessage  );
			*packet << strings;
		}
		temp = packet;

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


