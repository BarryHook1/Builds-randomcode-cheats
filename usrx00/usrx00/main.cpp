#include "main.h"
#include "DriverManager.h"


int main() {
	std::unique_ptr<DriverManager> driver = std::make_unique<DriverManager>("\\\\.\\NTIOLib_MB");

	std::cout << "Wait please......" << std::endl;

	// RustClient.exe
	
	while (!driver->GetProcessID("dummy.exe"))
		std::this_thread::sleep_for(std::chrono::seconds(1));

	std::system("cls");

	std::this_thread::sleep_for(std::chrono::seconds(5));

	std::cout << std::hex << "0x" << driver->GetModuleBaseAddr("dummy.exe") << std::endl;


	std::cin.get();
}
