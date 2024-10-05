#include <windows.h>  
#include <stdio.h>

#include "../Common/common.h"

using Func_NtQueryIntervalProfile = NTSTATUS(__fastcall*)(IN ULONG ulCode, OUT PULONG ret);
Func_NtQueryIntervalProfile func_NtQueryIntervalProfile = nullptr;

int main()
{
    // 提权
    if (!tool::AdjustProcessTokenPrivilege())
    {
        LOG("AdjustProcessTokenPrivilege failed");
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
    if (exit_code)
    {
        LOG("richstuff process exit with nonzero code: %d", exit_code);
        return exit_code;
    }

    // 初始化通信
    HMODULE hNtdll = ::LoadLibraryA("ntdll.dll");
    if (NULL == hNtdll)
    {
        LOG("LoadLibraryA failed");
        return -1;
    }
    func_NtQueryIntervalProfile = (Func_NtQueryIntervalProfile)::GetProcAddress(hNtdll, "NtQueryIntervalProfile");
    if (NULL == func_NtQueryIntervalProfile)
    {
        LOG("GetProcAddress failed");
        return -1;
    }
    PMSG pMsg = (PMSG)malloc(sizeof(MSG));
    if (NULL == pMsg)
    {
        LOG("malloc failed");
        return -1;
    }
    ZeroMemory(pMsg, sizeof(MSG));
    LOG("Msg Address: 0x%llx Size: %d", (UINT64)pMsg, sizeof(MSG));

    // 通信测试
    ULONG ulRet = 0;
    func_NtQueryIntervalProfile(COMM::TEST_CODE, &ulRet);
    if (COMM::TEST_CODE != ulRet)
    {
        LOG("test communication failed, ret code: 0x%x", ulRet);
        return -1;
    }

    // 发送MSG地址给驱动
    uint32_t msg_addr_part_1 = static_cast<uint32_t>(((uint64_t)pMsg & 0x000000000000FFFFi64) >> 00) | COMM::MSG_PART_1;
    uint32_t msg_addr_part_2 = static_cast<uint32_t>(((uint64_t)pMsg & 0x00000000FFFF0000i64) >> 16) | COMM::MSG_PART_2;
    uint32_t msg_addr_part_3 = static_cast<uint32_t>(((uint64_t)pMsg & 0x0000FFFF00000000i64) >> 32) | COMM::MSG_PART_3;
    uint32_t msg_addr_part_4 = static_cast<uint32_t>(((uint64_t)pMsg & 0xFFFF000000000000i64) >> 48) | COMM::MSG_PART_4;
    func_NtQueryIntervalProfile(msg_addr_part_1, &ulRet);
    if (msg_addr_part_1 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return -1;
    }
    func_NtQueryIntervalProfile(msg_addr_part_2, &ulRet);
    if (msg_addr_part_2 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return -1;
    }
    func_NtQueryIntervalProfile(msg_addr_part_3, &ulRet);
    if (msg_addr_part_3 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return -1;
    }
    func_NtQueryIntervalProfile(msg_addr_part_4, &ulRet);
    if (msg_addr_part_4 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return -1;
    }

    // 发送命令
    func_NtQueryIntervalProfile(COMM::CTRL_CODE, &ulRet);
    if (COMM::CTRL_CODE != ulRet)
    {
        LOG("send control code failed, ret code: 0x%x", ulRet);
        return -1;
    }

    if (pMsg)
    {
        free(pMsg);
    }
    return 0;
}
