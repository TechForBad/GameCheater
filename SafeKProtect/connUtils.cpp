#include "connUtils.h"

typedef struct _HAL_PROFILE_SOURCE_INFORMATION
{
    KPROFILE_SOURCE Source;
    BOOLEAN Supported;
    ULONG Interval;
} HAL_PROFILE_SOURCE_INFORMATION, * PHAL_PROFILE_SOURCE_INFORMATION;

__int64(__fastcall* origin_HaliQuerySystemInformation)(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4);

__int64 __fastcall fun_HaliQuerySystemInformation(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4)
{
    if ((NULL == a3) || (UserMode != ExGetPreviousMode()) || (COMMUNICATION_CODE != a3->QuadPart))
    {
        return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
    }

    CHAR procName[300] = { 0 };
    ProcessUtils::GetProcessName(PsGetCurrentProcess(), procName);

    LOG_INFO("Process Name: %s, a3: 0x%llx, *a3: 0x%llx", procName, (UINT64)a3, a3->QuadPart);

    return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
}

BOOL ConnUtils::InitConnection()
{
    PVOID fun_NtQueryIntervalProfile = MemoryUtils::GetSSDTFunctionAddress("NtQueryIntervalProfile");
    if (NULL == fun_NtQueryIntervalProfile)
    {
        LOG_ERROR("GetSSDTFunctionAddress failed");
        return FALSE;
    }

    UINT64 dataPtr = (UINT64)MemoryUtils::FindPattern((BYTE*)fun_NtQueryIntervalProfile, 0x200, (BYTE*)"\xEB\xCC\xEB\xCC\xE8", "x?x?x");
    if (NULL == dataPtr)
    {
        LOG_ERROR("FindPattern failed");
        return FALSE;
    }
    dataPtr += 4;
    UINT64 fun_KeQueryIntervalProfile = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 1) + 5;
    dataPtr = (UINT64)MemoryUtils::FindPattern((BYTE*)fun_KeQueryIntervalProfile, 0x200, (BYTE*)"\x48\x8B\x05\xCC\xCC\xCC\xCC\xCC\x8D", "xxx?????x");
    UINT64 refFunc = (UINT64)dataPtr + *(PINT32)((PBYTE)dataPtr + 3) + 7;

    *(PVOID*)&origin_HaliQuerySystemInformation = InterlockedExchangePointer((PVOID*)refFunc, (PVOID)fun_HaliQuerySystemInformation);

    return TRUE;
}
