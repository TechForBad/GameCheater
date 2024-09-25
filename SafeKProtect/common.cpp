#include "common.h"

ULONG GetProcessNameOffset()
{
    static ULONG processNameOffset = 0;
    if (processNameOffset != 0)
    {
        return processNameOffset;
    }

    PEPROCESS curProc = PsGetCurrentProcess();
    for (int i = 0; i < 3 * PAGE_SIZE; ++i)
    {
        if (0 == strncmp(CHEAT_ENGINE_PROCESS_NAME, (PCHAR)curProc + i, strlen(CHEAT_ENGINE_PROCESS_NAME)))
        {
            processNameOffset = i;
            break;
        }
    }

    return processNameOffset;
}

BOOL GetProcessName(IN PEPROCESS proc, OUT PCHAR procName)
{
    ULONG processNameOffset = GetProcessNameOffset();
    if (0 == processNameOffset)
    {
        return FALSE;
    }
    strcpy(procName, (PCHAR)proc + processNameOffset);
    return TRUE;
}
