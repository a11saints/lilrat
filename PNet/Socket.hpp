#pragma once

#include "SocketHandle.hpp"
#include "PResult.hpp"
#include "IPVersion.hpp"
#include "SocketOptions.hpp"
#include "IPEndpoint.hpp"
#include "Constants.hpp"
#include "Packet.hpp"

namespace PNet {

	class Socket {

	public:
		Socket(IPVersion ipv = IPVersion::IPv4, SocketHandle sh = INVALID_SOCKET);
		PResult Create();
		PResult Close();
		PResult Bind(IPEndpoint endpoint);
		SocketHandle GetHandle();
		IPVersion GetIPVersion();
		PResult Send(const void* data, int NumberOfBytes, int& bytesSent);
		PResult Listen(IPEndpoint endpoint, int backlog=5);
		PResult Accept(Socket& outSocket, IPEndpoint * endpoint = nullptr);
		PResult Recv(void* destination, int numberOfBytes, int& bytesReceived);
		PResult RecvAll(void * destination, int numberOfBytes);
		PResult SendAll(const void * data, int numberOfBytes);
		PResult Connect(IPEndpoint endpoint);
		PResult Send(Packet& packet);
		PResult Recv(Packet &packet);
		PResult SetBlocking(bool isBlocking);

	private:
		PResult SetSocketOption(SocketOption option, bool value);
		IPVersion ipversion = IPVersion::IPv4;
		SocketHandle handle = INVALID_SOCKET;

	};

}