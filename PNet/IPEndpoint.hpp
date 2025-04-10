#pragma once
#include "IPVersion.hpp"
#include <WS2tcpip.h>

#include <string>
#include <vector>
namespace PNet {
	class IPEndpoint {
	public:
		IPEndpoint() {};
		IPEndpoint(const char* ip, unsigned short port);
		IPEndpoint(sockaddr* addr);
		IPVersion GetIPVersion ();
		std::string GetHostname ();
		std::string GetIPString();
		std::vector<uint8_t> GetIPBytes();
		sockaddr_in GetSockaddrIPv4();
		sockaddr_in6 GetSockaddrIPv6();
		void Print();
		unsigned short GetPort ();



	private:
		IPVersion ipversion = IPVersion::Unknown;
		std::string hostname = "";
		std::string ip_string = "";
		std::vector<uint8_t> ip_bytes;
		unsigned short port = 0;


	};
}