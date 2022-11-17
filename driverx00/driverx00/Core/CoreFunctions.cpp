#include "CoreFunctions.h"

PVOID driver::corefuncs::get_system_module_base(const char* module_name) {

	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return 0;


	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return 0;


	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp(reinterpret_cast<char*>(module[i].FullPathName), module_name) == 0)
		{
			module_base = module[i].ImageBase;
			module_size = reinterpret_cast<PVOID>(module[i].ImageSize);
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 0);

	if (module_base <= 0)
		return 0;

	return module_base;
}

BOOL driver::corefuncs::WriteToReadOnlyMemory(void* address, void* buffer, size_t size) {

	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl)
		return FALSE;

	// Locking and mapping memory with RW-rights:
	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	// Write your buffer to mapping:
	RtlCopyMemory(Mapping, buffer, size);

	// Resources freeing:
	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return TRUE;
}

PDRIVER_OBJECT driver::corefuncs::get_driver_objectptr(PUNICODE_STRING DriverName) {
	PDRIVER_OBJECT DrvObject;
	NTSTATUS status = STATUS_SUCCESS;

	status = ObReferenceObjectByName(DriverName, 0, NULL, 0, *IoDriverObjectType, KernelMode, NULL, reinterpret_cast<PVOID*>(&DrvObject));

	if (NT_SUCCESS(status)) return DrvObject;

	return NULL;
}

BOOL driver::hooks::CallKernelFunction(PVOID kernel_function_address) {
	

	UNICODE_STRING driver_name;
	RtlInitUnicodeString(&driver_name, L"\\Driver\\scmbusl");
	auto scmbusl_driver_object = driver::corefuncs::get_driver_objectptr(&driver_name);
		
	if (!scmbusl_driver_object) return FALSE;

	
	// hooking part.

	auto Original_MJFunctions_address = scmbusl_driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	
	if (!Original_MJFunctions_address) return FALSE;

	BYTE MJFuncs_original[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18 };

	BYTE shell_code_start[]
	{
		0x48, 0xB8 // mov rax, [xxx]
	};

	BYTE shell_code_end[]
	{
		0xFF, 0xE0, // jmp rax
		0xCC // 
	};

	RtlSecureZeroMemory(&MJFuncs_original, sizeof(MJFuncs_original));
	memcpy((PVOID)((ULONG_PTR)MJFuncs_original), &shell_code_start, sizeof(shell_code_start));
	uintptr_t test_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)MJFuncs_original + sizeof(shell_code_start)), &test_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)MJFuncs_original + sizeof(shell_code_start) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));


	driver::corefuncs::WriteToReadOnlyMemory(Original_MJFunctions_address, &MJFuncs_original, sizeof(MJFuncs_original));

	return TRUE;
}