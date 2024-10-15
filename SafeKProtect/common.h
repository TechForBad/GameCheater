#pragma once

#include "../Common/public_def.h"

#include "imports.h"
#include "communication.h"
#include "memoryUtils.h"
#include "processUtils.h"
#include "connUtils.h"
#include "fileUtils.h"
#include "apcUtils.h"
#include "shellcode.h"
#include "setCtxCall.h"
#include "OperDispatcher.h"

// 内存分配标志
#define MEM_TAG 'RICH'

const int kTrace{ 0 };
const int kInfo{ 1 };
const int kError{ 2 };

const static char* szLevel[] = { "TRACE", "INFO", "ERROR" };

template <typename... Args>
void log(int _level, const char* _file, int _line, const char* _fun, const char* fmt, Args... args)
{
    KdPrint(("[%s] %s(%d)::%s", szLevel[_level], _file, _line, _fun));
    KdPrint((fmt, args...));
}

#define LOG_TRACE(...) \
  log(kTrace, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
#define LOG_INFO(...) \
  log(kInfo, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
#define LOG_ERROR(...) \
  log(kError, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)

#define ProbeOutputType(pointer, type)                                        \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForWrite(pointer, sizeof(type), TYPE_ALIGNMENT(type))

#define ProbeInputType(pointer, type)                                         \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForRead(pointer, sizeof(type), TYPE_ALIGNMENT(type))

#define ProbeOutputBytes(pointer, size)                                       \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForWrite(pointer, size, TYPE_ALIGNMENT(BYTE))

#define ProbeInputBytes(pointer, size)                                        \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForRead(pointer, size, TYPE_ALIGNMENT(BYTE))

#define inl __forceinline

inl VOID WriteEnable()
{
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
}

inl VOID WriteDisable()
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
}

inl KTRAP_FRAME* PsGetTrapFrame(PETHREAD Thread = (PETHREAD)__readgsqword(0x188))
{
    return *(KTRAP_FRAME**)((ULONG64)Thread + 0x90);
}

inl void PsSetTrapFrame(PETHREAD Thread, KTRAP_FRAME* tf)
{
    *(KTRAP_FRAME**)((ULONG64)Thread + 0x90) = tf;
}

inl BOOLEAN IsProcessExit(PEPROCESS epro)
{
    if (!epro)
    {
        return TRUE;
    }

    return PsGetProcessExitStatus(epro) != STATUS_PENDING;
}

inl void KSleep(LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(10000 * milliseconds);  // convert milliseconds to 100 nanosecond intervals
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

PVOID GetCurrentProcessModule(const char* ModName, ULONG* ModSize = 0, bool force64 = 1);

inl PVOID GetModuleHandle(const char* ModName)
{
    return GetCurrentProcessModule(ModName);
}
