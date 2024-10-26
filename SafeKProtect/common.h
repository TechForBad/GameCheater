#pragma once

#include "../Common/public_def.h"

#include "imports.h"
#include "log.h"
#include "communication.h"
#include "memoryUtils.h"
#include "processUtils.h"
#include "connUtils.h"
#include "fileUtils.h"
#include "apcUtils.h"
#include "shellcode.h"
#include "setCtxCall.h"
#include "vmUtils.h"
#include "OperDispatcher.h"

#define MEM_TAG 'RICH'

#define inl __forceinline

#define __db __debugbreak
#ifdef _DEBUG
#define dbgdb __db
#define __dbgdb dbgdb
#else
#define dbgdb()
#define __dbgdb()
#endif

#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define ToUpper(Char) ((Char >= 'a' && Char <= 'z') ? (Char - 'a') : Char)
#define NT_HEADER(Base) (PIMAGE_NT_HEADERS)((ULONG64)(Base) + ((PIMAGE_DOS_HEADER)(Base))->e_lfanew)

template <typename StrType, typename StrType2>
inl BOOL StrICmp(StrType Str, StrType2 InStr, BOOL CompareFull)
{
    if (!Str || !InStr)
    {
        return false;
    }
    WCHAR c1, c2;
    do
    {
        c1 = *Str++;
        c2 = *InStr++;
        c1 = ToLower(c1);
        c2 = ToLower(c2);
        if (!c1 && (CompareFull ? !c2 : 1))
        {
            return true;
        }
    } while (c1 == c2);

    return FALSE;
}

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

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

inl BOOLEAN IsProcessExit(PEPROCESS pEprocess)
{
    if (NULL == pEprocess)
    {
        return TRUE;
    }
    return PsGetProcessExitStatus(pEprocess) != STATUS_PENDING;
}

inl VOID KSleep(LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(10000 * milliseconds);  // convert milliseconds to 100 nanosecond intervals
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

PVOID GetCurrentProcessModule(LPCSTR moduleName, ULONG* moduleSize = NULL, BOOL force64 = TRUE);

inl PVOID GetModuleHandle(LPCSTR ModName)
{
    return GetCurrentProcessModule(ModName);
}

PVOID GetProcAddress(PVOID moduleBase, LPCSTR funcName);

inl BOOLEAN IsValid(ULONG64 addr)
{
    if (addr < 0x1000)
    {
        return FALSE;
    }
    return MmIsAddressValid((PVOID)addr);
}

inl void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0)
{
    __stosb((PUCHAR)Ptr, Filling, Size);
}

inl void MemCpy(PVOID Destination, PVOID Source, SIZE_T Count)
{
    __movsb((PUCHAR)Destination, (PUCHAR)Source, Count);
}

inl PVOID KAlloc(ULONG64 Size, BOOL exec = FALSE, BOOL PagedPool = FALSE)
{
    PVOID buffer = ExAllocatePoolWithTag(
        PagedPool ? POOL_TYPE::PagedPool : (exec ? NonPagedPool : NonPagedPoolNx),
        Size,
        MEM_TAG
    );
    if (NULL == buffer)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        return NULL;
    }
    memset(buffer, 0, Size);
    return buffer;
}

inl void KFree(PVOID Ptr)
{
    if (Ptr)
    {
        ExFreePoolWithTag(Ptr, MEM_TAG);
    }
}

inl PVOID UAlloc(ULONG Size, ULONG Protect = PAGE_READWRITE, BOOL load = TRUE)
{
    PVOID AllocBase = nullptr; SIZE_T SizeUL = SizeAlign(Size);
#define LOCK_VM_IN_RAM 2
#define LOCK_VM_IN_WORKING_SET 1
    if (!ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocBase, 0, &SizeUL, MEM_COMMIT, Protect))
    {
        // ZwLockVirtualMemory(ZwCurrentProcess(), &AllocBase, &SizeUL, LOCK_VM_IN_WORKING_SET | LOCK_VM_IN_RAM);
        if (load)
        {
            MemZero(AllocBase, SizeUL);
        }
    }
    return AllocBase;
}

inl VOID UFree(PVOID Ptr)
{
    SIZE_T SizeUL = 0;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &Ptr, &SizeUL, MEM_RELEASE);
}

inl KTRAP_FRAME* PsGetTrapFrame(PETHREAD pEthread = (PETHREAD)__readgsqword(0x188))
{
    return *(KTRAP_FRAME**)((ULONG64)pEthread + 0x90);
}

inl VOID PsSetTrapFrame(PETHREAD pEthread, KTRAP_FRAME* tf)
{
    *(KTRAP_FRAME**)((ULONG64)pEthread + 0x90) = tf;
}
