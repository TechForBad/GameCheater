#include "connUtils.h"

__int64(__fastcall* origin_HaliQuerySystemInformation)(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4);

__int64 __fastcall fun_HaliQuerySystemInformation(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4)
{
    if ((1 != a1) || (24 != a2) || (NULL == a3) || (UserMode != ExGetPreviousMode()))
    {
        return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
    }

    CHAR procName[200] = { 0 };
    ProcessUtils::GetProcessName(PsGetCurrentProcess(), procName);

    Printf("Process Name: %s, a3: 0x%llx, *a3: 0x%llx", procName, (UINT64)a3, a3->QuadPart);

    return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
}

BOOL ConnUtils::InitConnection()
{
    PVOID fun_NtQueryIntervalProfile = MemoryUtils::GetSSDTFunctionAddress("NtQueryIntervalProfile");
    if (NULL == fun_NtQueryIntervalProfile)
    {
        Printf("Error! GetModuleExportAddress failed");
        return FALSE;
    }

    UINT64 dataPtr = (UINT64)MemoryUtils::FindPattern((BYTE*)fun_NtQueryIntervalProfile, 0x200, (BYTE*)"\xEB\xCC\xEB\xCC\xE8", "x?x?x");
    if (NULL == dataPtr)
    {
        Printf("Error! FindPattern failed");
        return FALSE;
    }
    dataPtr += 4;
    UINT64 fun_KeQueryIntervalProfile = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 1) + 5;
    dataPtr = (UINT64)MemoryUtils::FindPattern((BYTE*)fun_KeQueryIntervalProfile, 0x200, (BYTE*)"\x48\x8B\x05\xCC\xCC\xCC\xCC\xCC\x8D", "xxx?????x");
    UINT64 refFunc = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 3) + 7;

    *(PVOID*)&origin_HaliQuerySystemInformation = InterlockedExchangePointer((PVOID*)refFunc, (PVOID)fun_HaliQuerySystemInformation);

    return TRUE;
}
