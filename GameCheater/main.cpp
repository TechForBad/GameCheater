#include <windows.h>  
#include <stdio.h>

#include "../Common/common.h"

typedef enum _KPROFILE_SOURCE
{
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE;
using Func_NtQueryIntervalProfile = NTSTATUS(__fastcall*)(IN KPROFILE_SOURCE ProfileSource, OUT PULONG Interval);
Func_NtQueryIntervalProfile func_NtQueryIntervalProfile = nullptr;

int main()
{
    // 提权
    if (!tool::AdjustProcessTokenPrivilege())
    {
        LOG("AdjustProcessTokenPrivilege failed");
        return -1;
    }

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (NULL == hNtdll)
    {
        LOG("LoadLibraryA failed");
        return -1;
    }
    func_NtQueryIntervalProfile = (Func_NtQueryIntervalProfile)GetProcAddress(hNtdll, "NtQueryIntervalProfile");
    if (NULL == func_NtQueryIntervalProfile)
    {
        LOG("GetProcAddress failed");
        return -1;
    }

    // 输出重定向到父窗口控制台，方便观察打印日志
    AttachConsole(ATTACH_PARENT_PROCESS);
    if (NULL == freopen("CONOUT$", "w+t", stdout))
    {
        LOG("freopen failed");
        return -1;
    }

    // 启动进程加载自定义驱动
    wchar_t cur_dir_path[MAX_PATH] = { 0 };
    if (!tool::GetCurrentModuleDirPath(cur_dir_path))
    {
        LOG("GetCurrentModuleDirPath failed");
        return false;
    }
    std::wstring app_path = tool::Format(L"%ws%ws", cur_dir_path, CHEAT_ENGINE_FILE_NAME);
    std::wstring driver_path = tool::Format(L"%ws%ws", cur_dir_path, MY_DRIVER_NAME);
    std::wstring cmd_line = tool::Format(L"\"%ws\" -load_by_shellcode \"%ws\"", app_path.c_str(), driver_path.c_str());
    HANDLE hProcess = NULL;
    if (!tool::RunAppWithCommand(app_path.c_str(), cmd_line.c_str(), &hProcess))
    {
        ::CloseHandle(hProcess);
        LOG("RunAppWithCommand failed");
        return false;
    }

    // 等待进程结束
    ::WaitForSingleObject(hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(hProcess, &exit_code);
    ::CloseHandle(hProcess);
    if (!exit_code)
    {
        LOG("richstuff process exit with nonzero code: %d", exit_code);
        return exit_code;
    }


    KPROFILE_SOURCE profileSource = ProfileBranchMispredictions;
    ULONG interval = 0;
    func_NtQueryIntervalProfile(profileSource, &interval);

    return 0;
}
