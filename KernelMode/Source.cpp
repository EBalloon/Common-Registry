#include "utils.h"


NTSTATUS RegistryCallback(PVOID callbackContext, PVOID arg1, PVOID arg2) {

	UNREFERENCED_PARAMETER(callbackContext);

	if (INT(arg1) != 16) // RegNtPostSetValueKey
		return STATUS_SUCCESS;

	PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)arg2;
	PREG_SET_VALUE_KEY_INFORMATION preInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;

	if (RtlEqualUnicodeString(preInfo->ValueName, &MyKey, TRUE) == 0)
		return STATUS_SUCCESS;

	if (!preInfo->Data)
		return STATUS_SUCCESS;

	PREQUEST Data = *reinterpret_cast<PREQUEST*>(preInfo->Data);

	if (!Data)
		return STATUS_SUCCESS;

	if (!CurrentThread)
		CurrentThread = KeGetCurrentThread();

	switch (Data->Type)
	{

	// Read Memory
	case 1:
	{
		auto MemoryInfo = PCOPY_MEMORY(Data->Instruction);
		if (MemoryInfo->ProcessId && MemoryInfo->Source && MemoryInfo->Size)
		{
			auto Status = ReadProcessMemory(HANDLE(MemoryInfo->ProcessId), MemoryInfo->Source, &MemoryInfo->Destination, MemoryInfo->Size);
			if (NT_SUCCESS(Status))
				DbgPrintEx(0, 0, "Type: %d - Read Memory: %llu - Status: 0x%08X\n", Data->Type, uint64_t(MemoryInfo->Destination), Status);
		}
		break;
	}

	// Write Memory
	case 2:
	{
		
		break;
	}

	// Module Base
	case 3:
	{
		auto ModuleInfo = PMODULE_BASE(Data->Instruction);
		ModuleInfo->Base = GetModuleBaseProcess(HANDLE(ModuleInfo->ProcessId), ModuleInfo->ModuleName);
		if (ModuleInfo->Base)
			DbgPrintEx(0, 0, "Type: %d - Base: %p\n", Data->Type, ModuleInfo->Base);
		break;
	}
	
	}
	// ...

	return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(0, 0, "EntryPoint: %s\n", __FUNCTION__);

	// RegisterCallback
	RtlInitUnicodeString(&MyKey, L"MyRegID");
	auto Status = RegisterCallback(PEX_CALLBACK_FUNCTION(RegistryCallback), nullptr, &CmCookie);
	if (!NT_SUCCESS(Status))
		return Status;

	DbgPrintEx(0, 0, "Success!\n");

	return Status;
}