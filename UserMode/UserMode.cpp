#include <iostream>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

typedef struct _COPY_MEMORY {
	ULONG ProcessId;
	PVOID Destination;
	PVOID Source;
	SIZE_T Size;
} COPY_MEMORY, * PCOPY_MEMORY;

typedef struct _MODULE_BASE {
	ULONG ProcessId;
	LPCWSTR ModuleName;
	PVOID Base;
} MODULE_BASE, * PMODULE_BASE;

typedef struct _REQUEST {
	UINT32 Type;
	PVOID Instruction;
} REQUEST, * PREQUEST;

ULONG ProcessPid;

void ReadWriteRegistry(uint32_t type, void* instruction) {

	HKEY hKey = NULL;
	void* pointer = NULL;
	char Code[30] = "MyRegID";
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers", 0, KEY_ALL_ACCESS, &hKey);

	if (hKey != NULL && hKey != INVALID_HANDLE_VALUE) {

		auto SetRegistryValue = [&](BYTE* pointer, SIZE_T size, DWORD Type) -> BOOL
		{
			if (RegSetValueExA(hKey, Code, 0, Type, reinterpret_cast<BYTE*>(pointer), size) == ERROR_SUCCESS)
			{
				RegDeleteValue(hKey, Code);
				RegCloseKey(hKey);
				return TRUE;
			}
			return FALSE;
		};

		REQUEST request;

		request.Type = type;
		request.Instruction = instruction;

		pointer = &request;
		SetRegistryValue(reinterpret_cast<BYTE*>(&pointer), sizeof uintptr_t, REG_QWORD);
	}
}

template<typename T>
T ReadMemory(uint64_t address) {

	COPY_MEMORY Request;

	Request.ProcessId = ProcessPid;
	Request.Source = reinterpret_cast<void*>(address);
	Request.Size = sizeof(T);

	ReadWriteRegistry(1, &Request);

	auto result = reinterpret_cast<T>(Request.Destination);
	return result;
}

template<typename T>
void WriteMemory(uint64_t address, T Value) {

	COPY_MEMORY Request;

	Request.ProcessId = ProcessPid;
	Request.Source = reinterpret_cast<void*>(address);
	Request.Destination = reinterpret_cast<void*>(Value);
	Request.Size = sizeof(T);

	ReadWriteRegistry(2, &Request);
}

uint64_t GetModuleBase(LPCWSTR ModuleName) {

	MODULE_BASE Request;

	Request.ProcessId = ProcessPid;
	Request.ModuleName = ModuleName;

	ReadWriteRegistry(3, &Request);

	return reinterpret_cast<uint64_t>(Request.Base);
}

DWORD AttachProcess(std::string processName) {

	DWORD ProcessPid = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, processName.c_str()) == 0)
			{
				ProcessPid = entry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(snapshot);
	return ProcessPid;
}

int main()
{
	ProcessPid = AttachProcess("Paladins.exe");
	std::cout << "ProcessPid: " << ProcessPid << std::endl;

	if (!ProcessPid)
		system("pause");

	auto Base = GetModuleBase(L"Paladins.exe");
	std::cout << std::hex << "Base: 0x"  << Base << std::endl;

	if (!Base)
		system("pause");

	while (TRUE)
	{
		auto Value = ReadMemory<uint64_t>(Base + 0x77);
		printf("Value: %llu\n", Value);

		Sleep(1000);
	}

	system("pause");
}
