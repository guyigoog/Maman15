#include "InfoFilesHandler.h"
#include "Client.h"


int main()
{
	try {
		TransferInfo transferInfo = TransferInfo();
		Client* client = new Client(transferInfo);
		client->runProcess();
		delete client;
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "\FATAL ERROR: " << e.what() << std::endl;
		std::cerr << "Client shutted down" << std::endl;
		return -1;
	}
}