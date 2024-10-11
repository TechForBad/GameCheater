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

BOOL LoadDriver(const wchar_t* driverName, const wchar_t* driverPath)
{
    wchar_t szDriverImagePath[256] = { 0 };
    BOOL bRet = FALSE;
    SC_HANDLE hServiceMgr = NULL;   // SCM管理器的句柄
    SC_HANDLE hServiceDDK = NULL;   // NT驱动程序的服务句柄
    DWORD dwRtn;

    GetFullPathNameW(driverPath, 256, szDriverImagePath, NULL);

    // 打开服务控制管理器句柄hServiceMgr
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == hServiceMgr)
    {
        LOG("OpenSCManager failed");
        bRet = FALSE;
        goto BeforeLeave;
    }

    // 创建驱动所对应的服务句柄hServiceDDK
    hServiceDDK = CreateServiceW(
        hServiceMgr,            // 服务控制管理器句柄hServiceMgr
        driverName,             // 驱动程序的在注册表中的名字  
        driverName,             // 注册表驱动程序的 DisplayName 值  
        SERVICE_ALL_ACCESS,     // 加载驱动程序的访问权限  
        SERVICE_KERNEL_DRIVER,  // 表示加载的服务是驱动程序  
        SERVICE_DEMAND_START,   // 注册表驱动程序的 Start 值  
        SERVICE_ERROR_IGNORE,   // 注册表驱动程序的 ErrorControl 值  
        szDriverImagePath,      // 注册表驱动程序的 ImagePath 值  
        NULL,                   // GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
        NULL,
        NULL,
        NULL,
        NULL
    );

    // 判断服务是否失败
    if (NULL == hServiceDDK)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            LOG("CreateServiceW failed, last error: %d", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }

        // 驱动程序已经加载，只需要打开
        hServiceDDK = OpenServiceW(hServiceMgr, driverName, SERVICE_ALL_ACCESS);
        if (NULL == hServiceDDK)
        {
            // 如果打开服务也失败，则意味错误
            LOG("OpenServiceW failed");
            dwRtn = GetLastError();
            bRet = FALSE;
            goto BeforeLeave;
        }
    }

    // 开启此项服务
    bRet = StartServiceA(hServiceDDK, 0, NULL);
    if (!bRet)
    {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
        {
            LOG("StartServiceA failed, last error: %d", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            if (ERROR_IO_PENDING == dwRtn)
            {
                // 设备被挂住
                bRet = FALSE;
                goto BeforeLeave;
            }
            else
            {
                // 服务已经开启
                bRet = TRUE;
                goto BeforeLeave;
            }
        }
    }

    bRet = TRUE;

    // 离开前关闭句柄
BeforeLeave:
    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }

    return bRet;
}

BOOL UnloadDriver(const char* szSvrName)
{
    BOOL bRet = FALSE;
    SC_HANDLE hServiceMgr = NULL;   // SCM管理器的句柄
    SC_HANDLE hServiceDDK = NULL;   // NT驱动程序的服务句柄
    SERVICE_STATUS SvrSta;

    // 打开SCM管理器
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL)
    {
        // 带开SCM管理器失败
        LOG("OpenSCManager failed");
        bRet = FALSE;
        goto BeforeLeave;
    }

    // 打开驱动所对应的服务
    hServiceDDK = OpenServiceA(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);
    if (NULL == hServiceDDK)
    {
        // 打开驱动所对应的服务失败
        LOG("OpenServiceA failed");
        bRet = FALSE;
        goto BeforeLeave;
    }

    // 停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
    {
        LOG("ControlService failed");
    }

    // 动态卸载驱动程序
    if (!DeleteService(hServiceDDK))
    {
        // 卸载失败
        LOG("DeleteService failed");
    }

    bRet = TRUE;

    // 离开前关闭打开的句柄
BeforeLeave:
    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

bool GetProcessId(LPCWSTR processName, PDWORD pid)
{
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        LOG("CreateToolhelp32Snapshot failed");
        return false;
    }

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!::Process32First(hSnapshot, &processEntry))
    {
        LOG("Process32First failed");
        ::CloseHandle(hSnapshot);
        return false;
    }

    bool bFind = false;
    do
    {
        if (0 == wcscmp(processEntry.szExeFile, processName))
        {
            bFind = true;
            *pid = processEntry.th32ProcessID;
            break;
        }
    } while (::Process32Next(hSnapshot, &processEntry));

    ::CloseHandle(hSnapshot);
    return bFind;
}

PVOID LoadFileToMemory(const wchar_t* filePath, DWORD& fileBufferLen)
{
    HANDLE hFile = CreateFile(
        filePath,               // 文件路径
        GENERIC_READ,           // 访问权限：只读
        0,                      // 共享模式：该文件不能被其他程序访问
        NULL,                   // 安全属性
        OPEN_EXISTING,          // 打开方式：已存在的文件
        FILE_ATTRIBUTE_NORMAL,  // 文件属性
        NULL                    // 模板文件句柄
    );
    if (INVALID_HANDLE_VALUE == hFile)
    {
        LOG("CreateFile failed");
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (INVALID_FILE_SIZE == fileSize)
    {
        LOG("GetFileSize failed");
        CloseHandle(hFile);
        return NULL;
    }

    PVOID pFileBuffer = malloc(fileSize);
    if (NULL == pFileBuffer)
    {
        LOG("malloc failed");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD readedSize = 0;
    if (!ReadFile(hFile, pFileBuffer, fileSize, &readedSize, NULL) || fileSize != readedSize)
    {
        LOG("ReadFile failed");
        free(pFileBuffer);
        CloseHandle(hFile);
        return NULL;
    }

    fileBufferLen = fileSize;

    CloseHandle(hFile);
    return pFileBuffer;
}

BOOL CreateFullDump(HANDLE hProcess, DWORD pid, const char* dumpFilePath)
{
    // 创建转储文件
    HANDLE hDumpFile = CreateFileA(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hDumpFile)
    {
        LOG("CreateFileA failed, last error: %d", GetLastError());
        return FALSE;
    }

    // 写入转储文件
    BOOL success = MiniDumpWriteDump(
        hProcess,
        pid,
        hDumpFile,
        MiniDumpWithFullMemory,  // full dump
        NULL,
        NULL,
        NULL
    );
    if (!success)
    {
        LOG("MiniDumpWriteDump failed, last error: %d", GetLastError());
        CloseHandle(hDumpFile);
        return FALSE;
    }

    CloseHandle(hDumpFile);

    return TRUE;
}

}
