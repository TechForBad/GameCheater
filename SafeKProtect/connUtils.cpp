#include "connUtils.h"

typedef unsigned char   uint8;
#define _BYTE  uint8
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define BYTE4(x)   BYTEn(x,  4)

typedef unsigned int    uint32;
#define _DWORD uint32
#define DWORDn(x, n)  (*((_DWORD*)&(x)+n))
#define DWORD2(x)   DWORDn(x,  2)

static FuncConnectionCallback g_connectionCallback = NULL;

__int64(__fastcall* origin_HaliQuerySystemInformation)(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4);

__int64 __fastcall fun_HaliQuerySystemInformation(unsigned int a1, unsigned int a2, LARGE_INTEGER* a3, unsigned int* a4)
{
    if ((NULL == a3) || (a3->LowPart <= ProfileMaximum) || (UserMode != ExGetPreviousMode()))
    {
        return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
    }

    CHAR procName[300] = { 0 };
    ProcessUtils::GetProcessName(PsGetCurrentProcess(), procName);
    if (0 != _stricmp(procName, PROCESS_NAME_IN_EPROCESS_GAME_CHEATER))
    {
        return origin_HaliQuerySystemInformation(a1, a2, a3, a4);
    }

    ULONG ret = g_connectionCallback(a3->LowPart);
    BYTE4(a3->QuadPart) = 0x1;
    DWORD2(a3->QuadPart) = ret;

    return 0;
}

BOOL ConnUtils::InitConnection(FuncConnectionCallback connectionCallback)
{
    if (NULL == connectionCallback)
    {
        LOG_ERROR("Param error");
        return FALSE;
    }

    g_connectionCallback = connectionCallback;

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
