#include "common.h"

#include <tlhelp32.h>
#include <process.h>

namespace tool
{

std::string Format(const char* format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    int count = _vsnprintf(NULL, 0, format, argptr);
    va_end(argptr);

    va_start(argptr, format);
    char* buf = (char*)malloc(count * sizeof(char));
    if (NULL == buf)
    {
        return "";
    }
    _vsnprintf(buf, count, format, argptr);
    va_end(argptr);

    std::string str(buf, count);
    free(buf);
    return str;
}

std::wstring Format(const wchar_t* format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    int count = _vsnwprintf(NULL, 0, format, argptr);
    va_end(argptr);

    va_start(argptr, format);
    wchar_t* buf = (wchar_t*)malloc(count * sizeof(wchar_t));
    if (NULL == buf)
    {
        return L"";
    }
    _vsnwprintf(buf, count, format, argptr);
    va_end(argptr);

    std::wstring str(buf, count);
    free(buf);
    return str;
}

std::wstring ConvertCharToWString(const char* charStr)
{
    std::wstring wstr;
    int len = strlen(charStr);
    int size = MultiByteToWideChar(CP_UTF8, 0, charStr, len, NULL, NULL);
    if (size > 0)
    {
        wstr.resize(size);
        MultiByteToWideChar(CP_UTF8, 0, charStr, len, &wstr[0], size);
    }
    return wstr;
}

std::string ConvertWCharToString(const wchar_t* wcharStr)
{
    std::string str;
    int wlen = wcslen(wcharStr);
    int size = WideCharToMultiByte(CP_OEMCP, 0, wcharStr, wlen, NULL, 0, NULL, NULL);
    if (size > 0)
    {
        str.resize(size);
        WideCharToMultiByte(CP_OEMCP, 0, wcharStr, wlen, &str[0], size, NULL, NULL);
    }
    return str;
}

BOOL AdjustProcessTokenPrivilege()
{
    LUID luidTmp;
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        LOG("OpenProcessToken failed");
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp))
    {
        LOG("LookupPrivilegeValue failed");
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luidTmp;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
    {
        LOG("AdjustTokenPrivileges failed");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

bool GetCurrentModuleDirPath(WCHAR* dirPath)
{
    HMODULE hModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)GetCurrentModuleDirPath, &hModule);
    GetModuleFileName(hModule, dirPath, MAX_PATH);
    wchar_t* pos = wcsrchr(dirPath, L'\\');
    if (nullptr == pos)
    {
        LOG("wcsrchr failed");
        return false;
    }
    *(pos + 1) = L'\0';
    return true;
}

bool RunAppWithCommand(const wchar_t* application, const wchar_t* command, HANDLE* process)
{
    return RunAppWithRedirection(application, command, NULL, NULL, NULL, process);
}

bool RunAppWithRedirection(const wchar_t* application, const wchar_t* command,
                           HANDLE input, HANDLE output, HANDLE error, HANDLE* process)
{
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;

    memset(&si, 0, sizeof(si));

    if (!!input || !!output || !!error)
        si.dwFlags = STARTF_USESTDHANDLES;

    si.cb = sizeof(si);
    si.hStdInput = input ? input : ::GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = output ? output : ::GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = error ? error : ::GetStdHandle(STD_ERROR_HANDLE);

    wchar_t* command_dup = wcsdup(command);

    if (::CreateProcessW(application,
                         command_dup,
                         NULL,
                         NULL,
                         TRUE,
                         CREATE_NO_WINDOW,
                         NULL,
                         NULL,
                         &si,
                         &pi))
    {
        ::CloseHandle(pi.hThread);
        if (process == NULL)
            ::CloseHandle(pi.hProcess);
        else
            *process = pi.hProcess;
        free(command_dup);
        return true;
    }

    free(command_dup);
    return false;
}

}
