#include "common.h"

static ULONG g_processNameOffset = 0;

BOOL InitGetProcessNameOffset()
{
    PEPROCESS curProc = PsGetCurrentProcess();
    for (int i = 0; i < 3 * PAGE_SIZE; ++i)
    {
        if (0 == strncmp(CHEAT_ENGINE_PROCESS_NAME, (PCHAR)curProc + i, strlen(CHEAT_ENGINE_PROCESS_NAME)))
        {
            g_processNameOffset = i;
            break;
        }
    }

    return (g_processNameOffset != 0);
}

VOID GetProcessName(IN PEPROCESS proc, OUT PCHAR procName)
{
    strcpy(procName, (PCHAR)proc + g_processNameOffset);
    return;
}
