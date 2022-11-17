#include "../driverx00/Headers/driver.h"
#include "../driverx00/Core/CoreFunctions.h"
#include "../driverx00/Memory/MemoryFunctions.h"
#include "../driverx00/ClearTraces/ClearPIDcache.h"

typedef struct read
{
	UINT64 address;
	UINT32 something;
	UINT32 size;
} _read;

// communication struct. COMST
typedef struct COMST {
	ULONG64 BaseAddress;
	const char* moduleName;
	UINT64 SwitchCode;
	ULONG process_id;
	bool pidTraces_cleared;
	size_t size;
	uintptr_t address;
	void* buffer;
	bool write;
}_COMST;



NTSTATUS hook_handler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject); // not actually used.

	NTSTATUS Status = STATUS_SUCCESS;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);


	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == 0xC3506104) {
		_read* ReadInput = reinterpret_cast<_read*>(Irp->AssociatedIrp.SystemBuffer);


		_COMST* driver = reinterpret_cast<_COMST*>(ReadInput->address);

		switch (driver->SwitchCode)
		{
		case 0xCC11B198:
		{
			// get module base address.


			ANSI_STRING AS;
			UNICODE_STRING ModuleNAme;

			RtlInitAnsiString(&AS, driver->moduleName);
			RtlAnsiStringToUnicodeString(&ModuleNAme, &AS, TRUE);


			PEPROCESS process;
			PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(driver->process_id), &process);
			ULONG64 Base_Address64 = NULL;
			Base_Address64 = MemoryFuncs::GetModuleBasex64(process, ModuleNAme);
			driver->BaseAddress = Base_Address64;
			RtlFreeUnicodeString(&ModuleNAme);

			break;
		}
		case 0xAA11B198:
		{
			// read write memory.
			if (driver->write)
			{
				MemoryFuncs::WriteKMMemory(driver->process_id, driver->address, driver->buffer, driver->size);
			}
			else
			{
				// read
				MemoryFuncs::ReadKMMemory(driver->process_id, driver->address, &driver->buffer, driver->size);
			}

			break;
		}
		case 0xBB11B198:
		{
			// clear pidCache.
			if (ClearPIDB() != FALSE) driver->pidTraces_cleared = true; else driver->pidTraces_cleared = false;
			break;
		}
		default:
			break;
		}

	}

	// Complete the fake request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {

	// they are invalid for mapped drivers!
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);


	driver::hooks::CallKernelFunction(&hook_handler);

	return STATUS_SUCCESS;
}