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
#include "usermodeCallback.h"
#include "setCtxCall.h"
#include "OperDispatcher.h"

#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define ToUpper(Char) ((Char >= 'a' && Char <= 'z') ? (Char - 'a') : Char)
#define NT_HEADER(Base) (PIMAGE_NT_HEADERS)((ULONG64)(Base) + ((PIMAGE_DOS_HEADER)(Base))->e_lfanew)

template <typename StrType, typename StrType2>
__forceinline bool StrICmp(StrType Str, StrType2 InStr, bool CompareFull)
{
    if (!Str || !InStr) return false;
    wchar_t c1, c2; do
    {
        c1 = *Str++; c2 = *InStr++;
        c1 = ToLower(c1); c2 = ToLower(c2);
        if (!c1 && (CompareFull ? !c2 : 1))
            return true;
    } while (c1 == c2);

    return false;
}

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))

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

inl PVOID GetProcAddress(PVOID ModBase, const char* Name)
{
    if (!ModBase) return 0;
    //parse headers
    PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

    //process records
    for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
    {
        //get ordinal & name
        USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
        const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

        //check export name
        if (StrICmp(Name, ExpName, true))
            return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
    }

    //no export
    return nullptr;
}

inl BOOLEAN IsValid(ULONG64 addr)
{
    if (addr < 0x1000)
        return false;
    return MmIsAddressValid((PVOID)addr);
}

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

inl void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0)
{
    __stosb((PUCHAR)Ptr, Filling, Size);
}

inl void MemCpy(PVOID Destination, PVOID Source, SIZE_T Count)
{
    __movsb((PUCHAR)Destination, (PUCHAR)Source, Count);
}

inl PVOID UAlloc(ULONG Size, ULONG Protect = PAGE_READWRITE, bool load = true)
{
    PVOID AllocBase = nullptr; SIZE_T SizeUL = SizeAlign(Size);
#define LOCK_VM_IN_RAM 2
#define LOCK_VM_IN_WORKING_SET 1
    if (!ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocBase, 0, &SizeUL, MEM_COMMIT, Protect))
    {
        //ZwLockVirtualMemory(ZwCurrentProcess(), &AllocBase, &SizeUL, LOCK_VM_IN_WORKING_SET | LOCK_VM_IN_RAM);
        if (load)
            MemZero(AllocBase, SizeUL);
    }
    return AllocBase;
}
