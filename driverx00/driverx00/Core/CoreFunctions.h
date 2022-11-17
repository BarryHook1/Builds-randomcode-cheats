#pragma once
#include "../Headers/driver.h"
#include "../Headers/FunctionsDef.h"
#include "../Headers/NativeStructs.h"




namespace driver{
	namespace corefuncs{
		PVOID get_system_module_base(const char* module_name);
		BOOL WriteToReadOnlyMemory(void* address, void* buffer, size_t size);
		PDRIVER_OBJECT get_driver_objectptr(PUNICODE_STRING DriverName);
	}
	namespace hooks{
		BOOL CallKernelFunction(PVOID kernel_function_address);
	}
}
