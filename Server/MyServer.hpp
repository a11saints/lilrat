#include <PNet/IncludeMe.hpp>
#include <string>

class MyServer : public Server {
private:
	void OnConnect(TCPConnection& newConnection) override ;
	void OnDisconnect(TCPConnection& lostConnection, std::string reason) override;
	bool ProcessPacket(std::shared_ptr<Packet> packet) override;
    void CreatePacket(TCPConnection& newConnection, std::string message) override ;

};

