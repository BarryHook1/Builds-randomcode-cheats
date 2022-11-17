#pragma once
#include "driver.h"

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineNam
);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

extern "C" NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);


extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C" typedef NTSTATUS(NTAPI OBREFERENCEOBJECTBYNAME) (
	PUNICODE_STRING ObjectPath,
	ULONG Attributes,
	PACCESS_STATE PassedAccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID* ObjectPtr);

extern "C" __declspec(dllimport) OBREFERENCEOBJECTBYNAME ObReferenceObjectByName;
extern "C" __declspec(dllimport) POBJECT_TYPE * IoDriverObjectType;