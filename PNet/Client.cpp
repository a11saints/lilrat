#include "Client.hpp"
#include <iostream>
//#include "CMD.hpp"

namespace PNet {
	Client::Client() {
		std::cout << "\n[=] Client [=]";
		clientUPtr = std::unique_ptr<Client>();
	}
	Client::~Client() {
	}
	bool Client::Connect(IPEndpoint ip) {
		isConnected = false;
		Socket socket = Socket(ip.GetIPVersion());
		
		if (socket.Create() == PResult::P_Success) {
			if (socket.SetBlocking(true) != PResult::P_Success) {
				return false;
			}
			std::cout << "\n[+] Socket successfully created.";
			if (socket.Connect(ip) == PResult::P_Success) {
				if (socket.SetBlocking(false) == PResult::P_Success) {
					connection = TCPConnection(socket, ip);
					master_fd.fd = connection.socket.GetHandle();
					master_fd.events = POLLRDNORM;
					master_fd.revents = 0;
					isConnected = true;
					OnConnect();
					return true;
				}
			}
			
			else {
				std::cerr << "\n[-] Failed to conntected to server." ;
				socket.Close();
			}
		}
		else {
			std::cerr << "\n[-] Socket failed to create.";
		}
		OnConnectFail();
		return false;
	}

	bool Client::IsConnected() {
		return isConnected;
	}

	bool Client::Frame() {
		if (connection.pm_outgoing.HasPendingPackets()) {
			master_fd.events = POLLRDNORM | POLLWRNORM;

		}
		use_fd = master_fd;

		if (WSAPoll(&use_fd, 1, 1) > 0) {

			if (use_fd.revents & POLLERR) {
				CloseConnection("POLLERR");
				return false;
			}

			if (use_fd.revents & POLLHUP) {
				CloseConnection("POLLHUP");

				return false;
			}

			if (use_fd.revents & POLLNVAL) {
				CloseConnection("POLLNVAL");
				return false;
			}
			
			if (use_fd.revents & POLLRDNORM) {

				int bytesReceived = 0;
				if (connection.pm_incoming.currentTask == PacketManagerTask::ProcessPacketSize) {
					bytesReceived = recv(
						use_fd.fd, 
						(char*)&connection.pm_incoming.currentPacketSize + connection.pm_incoming.currentPacketExtractionOffset, 
						sizeof(uint16_t) - connection.pm_incoming.currentPacketExtractionOffset, 
						0);
				}
				else {
					bytesReceived = recv(
						use_fd.fd, 
						(char*)&connection.buffer + connection.pm_incoming.currentPacketExtractionOffset, 
						connection.pm_incoming.currentPacketSize - connection.pm_incoming.currentPacketExtractionOffset, 
						0);
				}

				if (bytesReceived == 0) {
					CloseConnection("Recv==0");
					return false;
				}
				if (bytesReceived == SOCKET_ERROR) {
					int error = WSAGetLastError();
					if (error != WSAEWOULDBLOCK) {
						CloseConnection("Recv<0");
						return false;
					}
				}

				if (bytesReceived > 0) {
					connection.pm_incoming.currentPacketExtractionOffset += bytesReceived;
					if (connection.pm_incoming.currentTask == PacketManagerTask::ProcessPacketSize) {
						if (connection.pm_incoming.currentPacketExtractionOffset == sizeof(uint16_t)) {
							connection.pm_incoming.currentPacketSize = ntohs(connection.pm_incoming.currentPacketSize);
							if (connection.pm_incoming.currentPacketSize > PNet::g_MaxPacketSize) {
								CloseConnection("Packet size too large.");
								return false;
							}
							connection.pm_incoming.currentPacketExtractionOffset = 0;
							connection.pm_incoming.currentTask = PacketManagerTask::ProcessPacketContents;
						}
					}
					else {
						if (connection.pm_incoming.currentPacketExtractionOffset == connection.pm_incoming.currentPacketSize) {
							std::shared_ptr<Packet> packet = std::make_shared<Packet>();
							packet->buffer.resize(connection.pm_incoming.currentPacketSize);
							memcpy(&packet->buffer[0], connection.buffer, connection.pm_incoming.currentPacketSize);
							connection.pm_incoming.Append(packet);
							connection.pm_incoming.currentPacketSize = 0;
							connection.pm_incoming.currentPacketExtractionOffset = 0;
							connection.pm_incoming.currentTask = PacketManagerTask::ProcessPacketSize;
						}
					}
				}
			}

			if (use_fd.revents & POLLWRNORM) {
				PacketManager& pm = connection.pm_outgoing;
				while (pm.HasPendingPackets()) {
					if (pm.currentTask == PacketManagerTask::ProcessPacketSize) {
						pm.currentPacketSize = pm.Retrieve()->buffer.size();
						uint16_t bigEndPacketSize = htons(pm.currentPacketSize);
						int bytesSent = send(use_fd.fd, (char*)(&bigEndPacketSize) + pm.currentPacketExtractionOffset, sizeof(uint16_t) - pm.currentPacketExtractionOffset, 0);
						if (bytesSent > 0) {
							pm.currentPacketExtractionOffset += bytesSent;
						}
						if (pm.currentPacketExtractionOffset == sizeof(uint16_t)) {
							pm.currentPacketExtractionOffset = 0;
							pm.currentTask = PacketManagerTask::ProcessPacketContents;
						}
						else {
							break;
						}

					}
					else {
						char* bufferPtr = &pm.Retrieve()->buffer[0];
						int bytesSent = send(use_fd.fd, (char*)(bufferPtr)+pm.currentPacketExtractionOffset, pm.currentPacketSize - pm.currentPacketExtractionOffset, 0);
						if (bytesSent > 0) {
							pm.currentPacketExtractionOffset += bytesSent;
						}
						if (pm.currentPacketExtractionOffset == pm.currentPacketSize) {
							pm.currentPacketExtractionOffset = 0;
							pm.currentTask = PacketManagerTask::ProcessPacketSize;
							pm.Pop();
						}
						else {
							break;
						}
					}
				}
				if (!connection.pm_outgoing.HasPendingPackets()) {
					master_fd.events = POLLRDNORM;
				}
			}
		}
		// Removed to support cmd functions. [1]
	 	
	while (connection.pm_incoming.HasPendingPackets()) {
		std::shared_ptr<Packet> frontPacket = connection.pm_incoming.Retrieve();
		if (!ProcessPacket(frontPacket)) {
			CloseConnection("\n[-] Failed to process incoming packet.");
			return false;
		}
		connection.pm_incoming.Pop();
		}
	}

	bool Client::ProcessPacket(std::shared_ptr<Packet> packet) {
		
		/*   commented out for now, maybe reimplement later
		switch (packet->GetPacketType()) {
			case PT_ChatMessage: {
			}
			case PacketType::PT_Shell: {
				//CMD cmd(*clientUPtr);
				//cmd.SpawnChildProcess();
				//cmd.CMDStart();
				std::cout << "[+] Shell started:" << std::endl << "\t";
			}
			case PT_Command: {
			}
		}
		*/
		
		std::cout << "\n[+] Packet received with size: " << packet->buffer.size();
		return true;
	}

	void Client::OnConnect() {
		std::cout << "\n[+] Successfully connected! " ;
	}

	void Client::OnConnectFail() {
		std::cout << "\n[+] Failed to connect. " ;
	}

	void Client::OnDisconnect(std::string reason) {
		std::cout << "\n[+] Lost connection. Reason: " << reason << "." ;
	}

	void Client::CloseConnection(std::string reason) {
		OnDisconnect(reason);
		master_fd.fd = 0;
		isConnected = false;
		connection.Close();
	}
}

