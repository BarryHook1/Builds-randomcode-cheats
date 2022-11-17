#include "MemoryFunctions.h"


ULONG64 MemoryFuncs::GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb) {
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}



	// loop the linked list
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}
	KeUnstackDetachProcess(&state);

	return 0; // failed
}


NTSTATUS MemoryFuncs::ReadKMMemory(ULONG processid, uintptr_t address, void* buffer, size_t size) {
	SIZE_T bytesRead = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(processid), &process);

	if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;
	
	status = MmCopyVirtualMemory(process, reinterpret_cast<void*>(address), PsGetCurrentProcess(), buffer, size, KernelMode, &bytesRead);

	if (!NT_SUCCESS(status)) return status;

	return status;
}


NTSTATUS MemoryFuncs::WriteKMMemory(ULONG processid, uintptr_t address, void* buffer, size_t size) {
	SIZE_T bytesWrote = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(processid), &process);

	if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;

	status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer,process , reinterpret_cast<void*>(address), size, KernelMode, &bytesWrote);

	if (!NT_SUCCESS(status)) return status;

	return status;
}