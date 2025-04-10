#include "Server.hpp"
#include <iostream>
#include "Network.hpp"

namespace PNet{ 
bool Server::Initialize(IPEndpoint ip)
{
	std::cout << "\n[=] Server [=]";

	master_fd.clear();
	connections.clear();

	listeningSocket = Socket(ip.GetIPVersion());

	if (listeningSocket.Create() == PResult::P_Success) {
		std::cout << "\n[+] Socket successfully created." ;
		if (listeningSocket.Listen(ip) == PResult::P_Success) {

			WSAPOLLFD listeningSocketFD = {};
			listeningSocketFD.fd = listeningSocket.GetHandle();
			listeningSocketFD.events = POLLRDNORM;
			listeningSocketFD.revents = 0;

			master_fd.push_back(listeningSocketFD);


			std::cout << "\n[+] Socket successfully listening.";
			return true;
		}
		else {
			std::cerr << "\n[-] Failed to listen.";
		}

		listeningSocket.Close();
	}
	else {
		std::cerr << "\n[-] Socket faield to cteate." ;
	}

	return false;
}

void Server::Frame() {
	for (int i = 0; i < connections.size(); i++) {
		if (connections[i].pm_outgoing.HasPendingPackets()) {
			master_fd[i + 1].events = POLLRDNORM | POLLWRNORM;
		}
	}
	use_fd = master_fd;


	if (WSAPoll(use_fd.data(), use_fd.size(), 1) > 0) {
#pragma region listener 
		WSAPOLLFD& listeningSocketFD = use_fd[0];
		if (listeningSocketFD.revents & POLLRDNORM) {
			Socket newConnectionSocket;
			IPEndpoint newConnectionEndpoint;
			if (listeningSocket.Accept(newConnectionSocket, &newConnectionEndpoint) == PResult::P_Success) {
				connections.emplace_back(TCPConnection(newConnectionSocket, newConnectionEndpoint));
				TCPConnection& acceptedConnection = connections[connections.size() - 1];
				WSAPOLLFD newConnectionFD = {};
				newConnectionFD.fd = newConnectionSocket.GetHandle();
				newConnectionFD.events = POLLRDNORM ;
				newConnectionFD.revents = 0;
				master_fd.push_back(newConnectionFD);
				OnConnect(acceptedConnection);
			} 
			else { 
				std::cerr << "\n[-] Failed to accept new connection.";
			}
		}
#pragma endregion Code specific to the listening socket
		for (int i = use_fd.size() - 1; i >= 1; i--)
		{
			int connectionIndex = i - 1;
			TCPConnection& connection = connections[connectionIndex];

			if (use_fd[i].revents & POLLERR) {
				CloseConnection(connectionIndex, "POLLERR");

				continue;
			}

			if (use_fd[i].revents & POLLHUP) {
				CloseConnection(connectionIndex, "POLLHUP");

				continue;
			}

			if (use_fd[i].revents & POLLNVAL) {
				CloseConnection(connectionIndex, "POLLNVAL");
				continue;
			}

			if (use_fd[i].revents & POLLRDNORM) {

				int bytesReceived = 0;

				if (connection.pm_incoming.currentTask == PacketManagerTask::ProcessPacketSize) {
					bytesReceived = recv(
						use_fd[i].fd, 
						(char*)&connection.pm_incoming.currentPacketSize + connection.pm_incoming.currentPacketExtractionOffset,
						sizeof(uint16_t) - connection.pm_incoming.currentPacketExtractionOffset,
						0);
				}
				else {
					bytesReceived = recv(
						use_fd[i].fd,
						(char*)&connection.buffer + connection.pm_incoming.currentPacketExtractionOffset,
						connection.pm_incoming.currentPacketSize - connection.pm_incoming.currentPacketExtractionOffset,
						0);

				}

				if (bytesReceived == 0) {
					CloseConnection(connectionIndex, "Recv==0");
					continue;
				}
				if (bytesReceived == SOCKET_ERROR) {
					int error = WSAGetLastError();
					if (error != WSAEWOULDBLOCK) {
						CloseConnection(connectionIndex, "Recv<0");
						continue;
					}

				}

				if (bytesReceived > 0) {
					connection.pm_incoming.currentPacketExtractionOffset += bytesReceived;
					if (connection.pm_incoming.currentTask == PacketManagerTask::ProcessPacketSize) {
						if (connection.pm_incoming.currentPacketExtractionOffset == sizeof(uint16_t)) {
							connection.pm_incoming.currentPacketSize = ntohs(connection.pm_incoming.currentPacketSize);
							if (connection.pm_incoming.currentPacketSize > PNet::g_MaxPacketSize) {
								CloseConnection(connectionIndex, "Packet size too large.");
								continue;
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

			if (use_fd[i].revents & POLLWRNORM) {

				PacketManager& pm = connection.pm_outgoing;
				while (pm.HasPendingPackets()) {
					if (pm.currentTask == PacketManagerTask::ProcessPacketSize) {
						pm.currentPacketSize = pm.Retrieve()->buffer.size();
						uint16_t bigEndPacketSize = htons(pm.currentPacketSize);
						int bytesSent = send(use_fd[i].fd, (char*)(&bigEndPacketSize) + pm.currentPacketExtractionOffset, sizeof(uint16_t) - pm.currentPacketExtractionOffset, 0);
						if (bytesSent > 0) {
							pm.currentPacketExtractionOffset += bytesSent;
						}
						if (pm.currentPacketExtractionOffset == sizeof(uint16_t))
						{
							pm.currentPacketExtractionOffset = 0;
							pm.currentTask = PacketManagerTask::ProcessPacketContents;
						}
						else {
							break;
						}

					}
					else {
						char* bufferPtr = &pm.Retrieve()->buffer[0];
						int bytesSent = send(use_fd[i].fd, (char*)(bufferPtr)+pm.currentPacketExtractionOffset, pm.currentPacketSize - pm.currentPacketExtractionOffset, 0);
						if (bytesSent > 0) {
							pm.currentPacketExtractionOffset += bytesSent;
						}
						if (pm.currentPacketExtractionOffset == pm.currentPacketSize)
						{
							pm.currentPacketExtractionOffset = 0;
							pm.currentTask = PacketManagerTask::ProcessPacketSize;
							pm.Pop();

						}
						else {
							break;
						}
					}
				}
				if (!pm.HasPendingPackets())
				{
					master_fd[i].events = POLLRDNORM;


				}
			}
		}
	}

	for (int i = connections.size() - 1; i >= 0; i--) {

		while (connections[i].pm_incoming.HasPendingPackets()) {

			std::shared_ptr<Packet> frontPacket = connections[i].pm_incoming.Retrieve();
			if (!ProcessPacket(frontPacket)) {
				CloseConnection(i, "\n[-] Failed to process incoming packet.");
				break;
			}
			connections[i].pm_incoming.Pop();
		}
	}


}
std::vector<TCPConnection>& Server::GetConnectionsList() {
	return connections;
}
void Server::CreatePacket(TCPConnection& newConnection, std::string message) {

}


void Server::OnConnect(TCPConnection& newConnection) {
	std::cout << newConnection.ToString() << "\n[+] New connection accepted." ;
}
void Server::OnDisconnect(TCPConnection& lostConnection, std::string reason) {
	std::cout << "[" << reason << "] Connection lost: " << lostConnection.ToString() << "." << std::endl;
}

void Server::CloseConnection(int connectionIndex, std::string reason) {
	TCPConnection& connection = connections[connectionIndex];
	OnDisconnect(connection, reason);
	master_fd.erase(master_fd.begin() + (connectionIndex + 1));
	use_fd.erase(use_fd.begin() + (connectionIndex + 1));
	connection.Close();
	connections.erase(connections.begin() + connectionIndex);
}

bool Server::ProcessPacket(std::shared_ptr<Packet> packet) {
	std::cout << "Packet received with size: " << packet->buffer.size() << std::endl;
	return true;
}
}