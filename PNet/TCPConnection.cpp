#include "TCPConnection.hpp"
using namespace PNet;

namespace PNet {
	TCPConnection::TCPConnection(Socket socket, IPEndpoint endpoint) :socket(socket),endpoint(endpoint)
	{
		stringRepresentation = "\n[+] Endpoint - [" + endpoint.GetIPString();
		stringRepresentation += ":" + std::to_string(endpoint.GetPort()) + "]";

	}

	void TCPConnection::Close()
	{
		socket.Close();
	}

	std::string TCPConnection::ToString()
	{
		return stringRepresentation;
	}

}