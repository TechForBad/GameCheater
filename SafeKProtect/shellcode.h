#pragma once

#include "common.h"

typedef NTSTATUS(WINAPI* FUN_LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* FUN_RTLINITANSISTRING)(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI* FUN_RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* FUN_LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI* FUN_NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

typedef struct _INJECTPARAM
{
    PVOID lpFileData;   // 我们要注射的DLL内容
    DWORD dwDataLength; // 我们要注射的DLL长度

    FUN_LDRGETPROCEDUREADDRESS       fun_LdrGetProcedureAddress;
    FUN_NTALLOCATEVIRTUALMEMORY      fun_NtAllocateVirtualMemory;
    FUN_LDRLOADDLL                   fun_LdrLoadDll;
    FUN_RTLINITANSISTRING            fun_RtlInitAnsiString;
    FUN_RTLANSISTRINGTOUNICODESTRING fun_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING			 fun_RtlFreeUnicodeString;
} INJECTPARAM;

PVOID GetShellCodeBuffer(ULONG& shellCodeSize);
