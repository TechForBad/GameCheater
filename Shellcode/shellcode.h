#pragma once

#include <windows.h>

#pragma warning(disable: 4996)

typedef _Null_terminated_ CHAR* PSZ;
typedef _Null_terminated_ CONST char* PCSZ;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
        _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* FUN_LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* FUN_RTLINITANSISTRING)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI* FUN_RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* FUN_LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI* FUN_NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef INT(WINAPI* MESSAGEBOXA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

typedef struct _INJECTPARAM
{
    PVOID lpFileData;   // 我们要注射的DLL内容
    DWORD dwDataLength; // 我们要注射的DLL长度
    DWORD dwTargetPID;  // 我们要注射的进程PID

    FUN_LDRGETPROCEDUREADDRESS       fun_LdrGetProcedureAddress;
    FUN_NTALLOCATEVIRTUALMEMORY      fun_NtAllocateVirtualMemory;
    FUN_LDRLOADDLL                   fun_LdrLoadDll;
    FUN_RTLINITANSISTRING            fun_RtlInitAnsiString;
    FUN_RTLANSISTRINGTOUNICODESTRING fun_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING			 fun_RtlFreeUnicodeString;
    MESSAGEBOXA						 fun_MessageBoxA;
} INJECTPARAM;

ULONG_PTR WINAPI MemoryLoadLibrary_Begin(INJECTPARAM* InjectParam);

void MemoryLoadLibrary_End();
