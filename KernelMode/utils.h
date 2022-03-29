#include <ntdef.h>
#include <intrin.h>
#include <ntifs.h>
#include <ntimage.h>

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef int                 PINT;
typedef unsigned long long uint64_t;

PKTHREAD CurrentThread = 0;

extern "C" PLIST_ENTRY NTKERNELAPI PsLoadedModuleList;
extern "C" PPEB NTKERNELAPI PsGetProcessPeb(PEPROCESS Process);
extern "C" NTSTATUS NTKERNELAPI ZwQuerySystemInformation( DWORD32 systemInformationClass, PVOID systemInformation,
	ULONG systemInformationLength, PULONG returnLength);

UCHAR ShellCode[] = {
	0x50,
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x87, 0x04, 0x24,
	0xC3
};

typedef struct _REQUEST {
	UINT32 Type;
	PVOID Instruction;
} REQUEST, * PREQUEST;

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

UNICODE_STRING MyKey;
LARGE_INTEGER CmCookie = { 0x3090 };

typedef struct _RegisterCallbackEntry
{
	LIST_ENTRY ListEntryHead;
	BOOLEAN PendingDelete;
	LARGE_INTEGER Cookie;
	void* Context;
	void* Routine;
} RegisterCallbackEntry, * PRegisterCallbackEntry;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union {
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _LDR_DEPENDENCY_RECORD
{
	SINGLE_LIST_ENTRY DependencyLink;
	PLDR_DDAG_NODE DependencyNode;
	SINGLE_LIST_ENTRY IncomingDependencyLink;
	PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, * PLDR_DEPENDENCY_RECORD;

typedef enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
* PLDR_DLL_LOAD_REASON;

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union {
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ReservedFlags5 : 3;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock;
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
	{
		if ('x' == *mask && *base != *pattern)
		{
			return FALSE;
		}
	}

	return TRUE;
}

UINT_PTR FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
{
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i)
	{
		UINT_PTR addr = UINT_PTR( &base[i] );

		if (CheckMask((PCHAR)addr, pattern, mask))
		{
			return addr;
		}
	}

	return 0;
}

UINT_PTR FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
{
	UINT_PTR match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if ('EGAP' == *(int*)section->Name || memcmp(section->Name, ".text", 5) == 0)
		{
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
			{
				break;
			}
		}
	}

	return match;
}

uint64_t GetModuleNtoskrnlBase()
{
	uint64_t Base;
	ULONG Size = 0;
	ZwQuerySystemInformation(11, &Size, 0, &Size);
	if (Size == 0)
		return false;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION sys_mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Size, tag);
	if (sys_mods == 0) 
		return false;

	NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, Size, 0);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(sys_mods, tag);
		return false;
	}

	for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
	{
		PSYSTEM_MODULE mod = &sys_mods->Modules[i];
		if (strstr(mod->ImageName, "ntoskrnl.exe"))
		{
			Base = (uint64_t)mod->Base;
			break;
		}
	}

	ExFreePoolWithTag(sys_mods, tag);
	return Base;
}

UINT_PTR GetModuleBase(LPCWSTR moduleName) {

	PLIST_ENTRY ModuleList = reinterpret_cast<PLIST_ENTRY>(PsLoadedModuleList);
	if (!ModuleList)
		return NULL;

	UNICODE_STRING pmoduleName{ };
	RtlInitUnicodeString(&pmoduleName, moduleName);

	for (auto entry = PsLoadedModuleList; entry != PsLoadedModuleList->Blink; entry = entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY Datatable = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (Datatable->BaseDllName.Length == pmoduleName.Length && RtlEqualUnicodeString(&Datatable->BaseDllName, &pmoduleName, TRUE)) {
			return reinterpret_cast<UINT_PTR>(Datatable->DllBase);
		}
	}

	return NULL;
}

UINT_PTR LookupCodecave(UINT_PTR ModuleBase, INT Size)
{
	auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleBase);
	auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(((BYTE*)dos_header + dos_header->e_lfanew));

	UINT_PTR start = 0, size = 0;

	UINT_PTR header_offset = (UINT_PTR)IMAGE_FIRST_SECTION(nt_headers);

	for (auto x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		auto* header = reinterpret_cast<IMAGE_SECTION_HEADER*>(header_offset);

		if (strcmp((CHAR*)header->Name, ".rdata") == 0)
		{
			start = (UINT_PTR)ModuleBase + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	UINT_PTR match = 0;
	INT cur_length = 0;

	for (auto cur = start; cur < start + size; ++cur)
	{
		if (*(BYTE*)cur == 0xCC)
		{
			if (!match)
				match = cur;

			if (++cur_length == Size)
				return match;
		}
		else
			match = cur_length = 0;
	}

	return NULL;
}

UINT_PTR GetCodeCave()
{
	UINT_PTR Driver = NULL;
	UINT_PTR IsCodeCave = 0;

	Driver = GetModuleBase(L"peauth.sys");
	if (Driver)
	{
		IsCodeCave = LookupCodecave(Driver, sizeof(ShellCode));
		if (IsCodeCave) {
			return IsCodeCave;
		}
	}

	return NULL;
}

bool ClearPFN(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages)
		return false;

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	return true;
};

PVOID
Sleep(
	ULONG Milliseconds
)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -1 * 10000LL * (LONGLONG)Milliseconds;
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	return NULL;
}

void
CopyList(IN PLIST_ENTRY Original,
	IN PLIST_ENTRY Copy,
	IN KPROCESSOR_MODE Mode)
{
	if (IsListEmpty(&Original[Mode]))
	{
		InitializeListHead(&Copy[Mode]);
	}
	else
	{
		Copy[Mode].Flink = Original[Mode].Flink;
		Copy[Mode].Blink = Original[Mode].Blink;
		Original[Mode].Flink->Blink = &Copy[Mode];
		Original[Mode].Blink->Flink = &Copy[Mode];
	}
}

void
MoveApcState(PKAPC_STATE OldState,
	PKAPC_STATE NewState)
{
	RtlCopyMemory(NewState, OldState, sizeof(KAPC_STATE));

	CopyList(OldState->ApcListHead, NewState->ApcListHead, KernelMode);
	CopyList(OldState->ApcListHead, NewState->ApcListHead, UserMode);
}

void AttachProcess(PEPROCESS NewProcess)
{
	PKTHREAD Thread = KeGetCurrentThread();

	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD::ApcState

	if (*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) == NewProcess) // 0x20 = _KAPC_STATE::Process
		return;

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) != 0)) // 0x24a = _KTHREAD::ApcStateIndex
	{
		KeBugCheck(INVALID_PROCESS_ATTACH_ATTEMPT);
		return;
	}

	MoveApcState(ApcState, *(PKAPC_STATE*)(uintptr_t(Thread) + 0x258)); // 0x258 = _KTHREAD::SavedApcState

	InitializeListHead(&ApcState->ApcListHead[KernelMode]);
	InitializeListHead(&ApcState->ApcListHead[UserMode]);

	*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) = NewProcess; // 0x20 = _KAPC_STATE::Process
	*(UCHAR*)(uintptr_t(ApcState) + 0x28) = 0;				// 0x28 = _KAPC_STATE::InProgressFlags
	*(UCHAR*)(uintptr_t(ApcState) + 0x29) = 0;				// 0x29 = _KAPC_STATE::KernelApcPending
	*(UCHAR*)(uintptr_t(ApcState) + 0x2a) = 0;				// 0x2a = _KAPC_STATE::UserApcPendingAll

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 1; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uint64_t*)(uint64_t(NewProcess) + 0x28);  // 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);
}

void DetachProcess()
{
	PKTHREAD Thread = KeGetCurrentThread();
	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD->ApcState

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) == 0)) // 0x24a = KTHREAD->ApcStateIndex
		return;

	if ((*(UCHAR*)(uintptr_t(ApcState) + 0x28)) ||  // 0x28 = _KAPC_STATE->InProgressFlags
		!(IsListEmpty(&ApcState->ApcListHead[KernelMode])) ||
		!(IsListEmpty(&ApcState->ApcListHead[UserMode])))
	{
		KeBugCheck(INVALID_PROCESS_DETACH_ATTEMPT);
	}

	MoveApcState(*(PKAPC_STATE*)(uintptr_t(Thread) + 0x258), ApcState); // 0x258 = _KTHREAD::SavedApcState
	*(PEPROCESS*)(*(uintptr_t*)(uintptr_t(Thread) + 0x258) + 0x20) = 0; // 0x258 = _KTHREAD::SavedApcState + 0x20 = _KAPC_STATE::Process

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 0; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uint64_t*)(uint64_t(*(PEPROCESS*)(uintptr_t(ApcState) + 0x20)) + 0x28); // 0x20 = _KAPC_STATE::Process + 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);

	if (!(IsListEmpty(&ApcState->ApcListHead[KernelMode])))
	{
		*(UCHAR*)(uint64_t(ApcState) + 0x29) = 1; // 0x29 = _KAPC_STATE::KernelApcPending
	}

	RemoveEntryList(&ApcState->ApcListHead[KernelMode]);
}

PHYSICAL_ADDRESS
SafeMmGetPhysicalAddress(PVOID BaseAddress)
{
	static BOOLEAN* KdEnteredDebugger = 0;
	if (!KdEnteredDebugger)
	{
		UNICODE_STRING UniCodeFunctionName = RTL_CONSTANT_STRING(L"KdEnteredDebugger");
		KdEnteredDebugger = reinterpret_cast<BOOLEAN*>(MmGetSystemRoutineAddress(&UniCodeFunctionName));
	}

	*KdEnteredDebugger = FALSE;
	PHYSICAL_ADDRESS PhysicalAddress = MmGetPhysicalAddress(BaseAddress);
	*KdEnteredDebugger = TRUE;

	return PhysicalAddress;
}

NTSTATUS ReadVirtualMemory(
	PEPROCESS Process,
	PVOID Destination,
	PVOID Source,
	SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	BOOLEAN IsAttached;

	// 1. Attach to the process
	//    Sets specified process's PML4 to the CR3
	AttachProcess(Process);
	IsAttached = TRUE;

	if (!MmIsAddressValid(Source))
		goto _Exit;

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = SafeMmGetPhysicalAddress(Source);

	// 3. Detach from the process
	//    Restores previous the current thread
	DetachProcess();
	IsAttached = FALSE;

	if (!SourcePhysicalAddress.QuadPart)
		return ntStatus;

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpaceEx(SourcePhysicalAddress, Size, PAGE_READWRITE);
	if (!MappedIoSpace)
		goto _Exit;

	// 5. copy memory
	memcpy(Destination, MappedIoSpace, Size);

	// 6. Free Map
	MmUnmapIoSpace(MappedIoSpace, Size);

	ntStatus = STATUS_SUCCESS;

_Exit:

	if (IsAttached)
		DetachProcess();

	return ntStatus;
}

NTSTATUS WriteVirtualMemory(
	PEPROCESS Process,
	PVOID Destination,
	PVOID Source,
	SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	BOOLEAN IsAttached;

	// 1. Attach to the process
	  //    Sets specified process's PML4 to the CR3
	AttachProcess(Process);
	IsAttached = TRUE;

	if (!MmIsAddressValid(Source))
		goto _Exit;

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = SafeMmGetPhysicalAddress(Source);

	// 3. Detach from the process
	//    Restores previous the current thread
	DetachProcess();
	IsAttached = FALSE;

	if (!SourcePhysicalAddress.QuadPart)
		return ntStatus;

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpaceEx(SourcePhysicalAddress, Size, PAGE_READWRITE);
	if (!MappedIoSpace)
		goto _Exit;

	// 5. copy memory
	memcpy(MappedIoSpace, Destination, Size);

	// 6. Free Map
	MmUnmapIoSpace(MappedIoSpace, Size);

	ntStatus = STATUS_SUCCESS;

_Exit:

	if (IsAttached)
		DetachProcess();
}

NTSTATUS ReadProcessMemory(HANDLE ProcessPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
	PEPROCESS Process = { 0 };
	auto ntStatus = PsLookupProcessByProcessId(ProcessPid, &Process);
	if (NT_SUCCESS(ntStatus) && Process)
	{
		ntStatus = ReadVirtualMemory(Process, Buffer, Address, Size);
	}

	ObDereferenceObject(Process);
	return ntStatus;
}

NTSTATUS WriteProcessMemory(HANDLE ProcessPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
	PEPROCESS Process = { 0 };
	auto ntStatus = PsLookupProcessByProcessId(ProcessPid, &Process);
	if (NT_SUCCESS(ntStatus) && Process)
	{
		ntStatus = WriteVirtualMemory(Process, Buffer, Address, Size);
	}

	ObDereferenceObject(Process);
	return ntStatus;
}

PVOID GetModuleBaseProcess(
	HANDLE ProcessId,
	LPCWSTR ModuleName
)
{
	PVOID mBase = 0;
	PEPROCESS Process = { 0 };

	UNICODE_STRING module_name = RTL_CONSTANT_STRING(ModuleName);
	if (ProcessId && NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(ProcessId), &Process)) && Process)
	{
		PPEB pPeb = PsGetProcessPeb(Process);

		AttachProcess(Process);

		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (RtlEqualUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) {
				mBase = pEntry->DllBase;
				break;
			}
		}

		DetachProcess();
	}

	return mBase;
}

BOOLEAN
WriteToReadOnly(PVOID destination,
	PVOID buffer,
	SIZE_T size
)
{
	PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
	if (!mdl)
		return FALSE;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

	auto mmMap = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	memcpy(mmMap, buffer, size);

	MmUnmapLockedPages(mmMap, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

uintptr_t GetCallbackListHead()
{
	uint64_t NtoskrnlBase = GetModuleNtoskrnlBase();
	if (!NtoskrnlBase)
		return 0;

	auto CallbackListHead = FindPatternImage(PCHAR(NtoskrnlBase),
		"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xF8\x48\x89\x44\x24\x00\x48\x85\xC0",
		"xxx????x????xxxxxxx?xxx");

	if (!CallbackListHead)
		return 0;

	CallbackListHead = reinterpret_cast<uintptr_t>(PCHAR(CallbackListHead) + 7 + *reinterpret_cast<INT*>(PCHAR(CallbackListHead) + 3));
	return uintptr_t(CallbackListHead);
}

NTSTATUS RegisterCallback(
	PEX_CALLBACK_FUNCTION  Function,
	PVOID Context,
	PLARGE_INTEGER Cookie
)
{
	LARGE_INTEGER LowAddress, HighAddress, SkipBytes;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xffffffffffffffffULL;
	SkipBytes.QuadPart = 0;

	auto CmiCallbackHead = PRegisterCallbackEntry(GetCallbackListHead());
	if (!CmiCallbackHead)
		return STATUS_INSUFFICIENT_RESOURCES;

	auto mdl = MmAllocatePagesForMdl(LowAddress, HighAddress, SkipBytes, sizeof(RegisterCallbackEntry));
	if (!mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	auto Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!Mapping) {
		MmFreePagesFromMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	const auto Protect = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(Protect)) {
		MmUnmapLockedPages(Mapping, mdl);
		MmFreePagesFromMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (!ClearPFN(mdl)) {
		MmUnmapLockedPages(Mapping, mdl);
		MmFreePagesFromMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	auto ListMap = PRegisterCallbackEntry(Mapping);

	auto IsCodeCave = GetCodeCave();
	if (!IsCodeCave)
		return STATUS_UNSUCCESSFUL;

	*(PVOID*)(ShellCode + 3) = reinterpret_cast<PVOID>(Function);

	if (!WriteToReadOnly(PVOID(IsCodeCave), ShellCode, sizeof(ShellCode)))
	{
		DbgPrintEx(0, 0, "Failed to Write To Read Only Memory");
		return STATUS_UNSUCCESSFUL;
	}

	ListMap->Routine = PVOID(IsCodeCave);
	ListMap->Context = Context;
	ListMap->PendingDelete = FALSE;
	ListMap->Cookie.QuadPart = 0; // put a random number
	
	InsertTailList(&CmiCallbackHead->ListEntryHead, &ListMap->ListEntryHead);

	*Cookie = ListMap->Cookie;

	return STATUS_SUCCESS;

	// Do this if you want to delete the callback later when you don't need it
	/*
	RemoveEntryList(&ListMap->ListEntryHead);
	*/
}

