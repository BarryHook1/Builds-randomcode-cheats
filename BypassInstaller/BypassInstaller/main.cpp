#include "BypassInstaller.h"


int main() 
{
	std::unique_ptr<BypassInstaller> bypass_installer = std::make_unique<BypassInstaller>();

	if (!bypass_installer->LoadVulnerableDriver())
		return -1;

	if (!bypass_installer->MapDriver("C:\\driverx00.sys", "driverx00.sys"))
		return -1;

	if (!bypass_installer->ClearMapperLogs())
		return -1;

	// if everything went fine.
	std::cout << "[+] bypass installed closing window in 1sec" << std::endl;

	std::this_thread::sleep_for(std::chrono::seconds(1));

	std::system("exit");

}