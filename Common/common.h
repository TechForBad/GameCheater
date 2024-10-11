#pragma once

#include <windows.h>
#include <string>
#include <thread>
#include <assert.h>
#include <iostream>
#include <filesystem>
#include <dbghelp.h>

#pragma warning(disable: 4996)

#pragma comment(lib, "Dbghelp.lib")

#include "public_def.h"
#include "../SafeKProtect/communication.h"
#include "DriverComm.h"
#include "InjectDll.h"

#define CONVERT_RVA(base, offset) ((PVOID)((PUCHAR)(base) + (ULONG)(offset)))

namespace tool
{

std::string Format(const char* format, ...);
std::wstring Format(const wchar_t* format, ...);

template <typename... Args>
inline void log(
    const char* tag, const char* _file, int _line, const char* _fun,
    const char* fmt, Args... args)
{
    std::string log = Format(fmt, args...);
    std::string allLog = Format("[%s]-%s(%d)::%s %s\n", tag, _file, _line, _fun, log.c_str());
    printf(allLog.c_str());
}

template <typename... Args>
inline void wlog(
    const char* tag, const char* _file, int _line, const char* _fun,
    const wchar_t* fmt, Args... args)
{
    std::wstring log = Format(fmt, args...);
    std::wstring allLog = Format(L"[%s]-%s(%d)::%s %ws\n", tag, _file, _line, _fun, log.c_str());
    wprintf(allLog.c_str());
}

// 字符串转换
std::wstring ConvertCharToWString(const char* charStr);
std::string ConvertWCharToString(const wchar_t* wcharStr);

// 提权
BOOL AdjustProcessTokenPrivilege();

// 模块获取自身所处文件夹目录
bool GetCurrentModuleDirPath(WCHAR* dirPath);

// 运行命令
bool RunAppWithCommand(const wchar_t* application, const wchar_t* command, HANDLE* process);
bool RunAppWithRedirection(const wchar_t* application, const wchar_t* command,
                           HANDLE input, HANDLE output, HANDLE error, HANDLE* process);

// 加载驱动
BOOL LoadDriver(const wchar_t* driverName, const wchar_t* driverPath);

// 卸载驱动
BOOL UnloadDriver(const char* szSvrName);

// 根据进程名获取进程号
bool GetProcessId(LPCWSTR processName, PDWORD pid);

// 加载文件到内存
PVOID LoadFileToMemory(const wchar_t* filePath, DWORD& fileBufferLen);

// 创建full dump
BOOL CreateFullDump(HANDLE hProcess, DWORD processID, const char* dumpFilePath);

}
