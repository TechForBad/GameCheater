#include "common.h"

#define NT_QWORD_SIG ("\x48\x8B\x05\x00\x00\x00\x00\x4C\x8D\x4C\x24\x60\xBA\x18\x00\x00\x00\x89\x4C\x24\x30\x4C\x8D\x44\x24\x30\x8D\x4A\xE9\xE8")
#define NT_QWORD_MASK ("xxx????xxxxxxxxxxxxxxxxxxxxxxx")

__int64(__fastcall* origin_HaliQuerySystemInformation)(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4);

__int64 __fastcall fun_HaliQuerySystemInformation(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4)
{
    if ((1 != a1) || (24 != a2) || (NULL == a3) || (UserMode != ExGetPreviousMode()))
    {
        return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
    }

	CHAR procName[200] = { 0 };
	GetProcessName(PsGetCurrentProcess(), procName);

	Printf("Process Name: %s, a3: 0x%llx, *a3: 0x%llx", procName, (UINT64)a3, a3->QuadPart);

    return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	Printf("Enter DriverEntry");

    if (!InitGetProcessNameOffset())
    {
        Printf("Error! InitGetProcessNameOffset failed");
        return STATUS_UNSUCCESSFUL;
    }

	UINT64 fun_NtQueryIntervalProfile = (UINT64)mem::GetSystemBaseModuleExport("\\SystemRoot\\system32\\ntoskrnl.exe", "NtQueryIntervalProfile");
	if (NULL == fun_NtQueryIntervalProfile)
	{
		Printf("Error! GetSystemBaseModuleExport failed");
		return STATUS_UNSUCCESSFUL;
	}

    UINT64 dataPtr = cleaner::FindPattern(fun_NtQueryIntervalProfile, 0x200, (BYTE*)"\xEB\xCC\xEB\xCC\xE8", "x?x?x");
	if (NULL == dataPtr)
	{
		Printf("Error! FindPattern failed");
		return STATUS_UNSUCCESSFUL;
	}
	dataPtr += 4;
	UINT64 fun_KeQueryIntervalProfile = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 1) + 5;
	dataPtr = cleaner::FindPattern(fun_KeQueryIntervalProfile, 0x200, (BYTE*)"\x48\x8B\x05\xCC\xCC\xCC\xCC\xCC\x8D", "xxx?????x");
	UINT64 refFunc = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 3) + 7;

    *(PVOID*)&origin_HaliQuerySystemInformation = InterlockedExchangePointer((PVOID*)refFunc, (PVOID)fun_HaliQuerySystemInformation);

	Printf("Leave DriverEntry");
	return STATUS_SUCCESS;
}
