#pragma once
#include "../Headers/driver.h"
#include "../Headers/FunctionsDef.h"
#include "../Headers/NativeStructs.h"



namespace MemoryFuncs{
	ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name);
	NTSTATUS ReadKMMemory(ULONG processid,uintptr_t address,void* buffer,size_t size);
	NTSTATUS WriteKMMemory(ULONG processid, uintptr_t address, void* buffer, size_t size);
}