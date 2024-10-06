#include "DriverComm.h"

bool DriverComm::Init()
{
    // 加载驱动
    if (!LoadDriver(TRUE))
    {
        LOG("LoadDriver failed");
        return false;
    }

    // 构建驱动通信
    if (!BuildDriverComm())
    {
        LOG("BuildDriverComm failed");
        return false;
    }

    // 通信测试
    if (!TestDriverComm())
    {
        LOG("TestDriverComm failed");
        return false;
    }

    is_init_ = true;

    return true;
}

bool DriverComm::LoadDriver(bool normalLoad)
{
    if (normalLoad)
    {
        if (!tool::LoadDriver(MY_DRIVER_NAME, MY_DRIVER_PATH))
        {
            LOG("LoadDriver failed");
            return false;
        }
    }
    else
    {
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
            LOG("RunAppWithCommand failed");
            return false;
        }

        // 等待进程结束
        ::WaitForSingleObject(hProcess, INFINITE);
        DWORD exit_code = 0;
        GetExitCodeProcess(hProcess, &exit_code);
        ::CloseHandle(hProcess);
        if (0 != exit_code)
        {
            LOG("richstuff process exit with nonzero code: %d", exit_code);
            return false;
        }
    }

    return true;
}

bool DriverComm::BuildDriverComm()
{
    // 初始化通信
    HMODULE hNtdll = ::GetModuleHandleA("ntdll.dll");
    if (NULL == hNtdll)
    {
        LOG("GetModuleHandleA failed");
        return false;
    }
    func_NtQueryIntervalProfile_ = (Func_NtQueryIntervalProfile)::GetProcAddress(hNtdll, "NtQueryIntervalProfile");
    if (NULL == func_NtQueryIntervalProfile_)
    {
        LOG("GetProcAddress failed");
        return false;
    }

    // 初始化CMSG
    ZeroMemory(&cmsg_, sizeof(COMM::CMSG));
    LOG("CMsg Address: 0x%llx Size: %d", &cmsg_, sizeof(COMM::CMSG));

    // 传递CMSG地址给驱动
    ULONG ulRet = 0;
    uint32_t msg_addr_part_1 = static_cast<uint32_t>(((uint64_t)&cmsg_ & 0x000000000000FFFFi64) >> 00) | COMM::MSG_PART_1;
    uint32_t msg_addr_part_2 = static_cast<uint32_t>(((uint64_t)&cmsg_ & 0x00000000FFFF0000i64) >> 16) | COMM::MSG_PART_2;
    uint32_t msg_addr_part_3 = static_cast<uint32_t>(((uint64_t)&cmsg_ & 0x0000FFFF00000000i64) >> 32) | COMM::MSG_PART_3;
    uint32_t msg_addr_part_4 = static_cast<uint32_t>(((uint64_t)&cmsg_ & 0xFFFF000000000000i64) >> 48) | COMM::MSG_PART_4;
    func_NtQueryIntervalProfile_(msg_addr_part_1, &ulRet);
    if (msg_addr_part_1 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return false;
    }
    func_NtQueryIntervalProfile_(msg_addr_part_2, &ulRet);
    if (msg_addr_part_2 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return false;
    }
    func_NtQueryIntervalProfile_(msg_addr_part_3, &ulRet);
    if (msg_addr_part_3 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return false;
    }
    func_NtQueryIntervalProfile_(msg_addr_part_4, &ulRet);
    if (msg_addr_part_4 != ulRet)
    {
        LOG("send msg addr failed, ret code: 0x%x", ulRet);
        return false;
    }

    return true;
}

bool DriverComm::TestDriverComm()
{
    ULONG ulRet = 0;
    func_NtQueryIntervalProfile_(COMM::TEST_CODE, &ulRet);
    if (COMM::TEST_CODE != ulRet)
    {
        LOG("test communication failed, ret code: 0x%x", ulRet);
        return false;
    }

    return true;
}

bool DriverComm::ReadProcessMemory(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst)
{
    if (!is_init_)
    {
        LOG("no init");
        return false;
    }

    ZeroMemory(&cmsg_, sizeof(COMM::CMSG));
    cmsg_.oper = COMM::Operation::Oper_ProcessMemoryRead;
    cmsg_.needOutput = false;
    cmsg_.input_MemoryRead.pid = pid;
    cmsg_.input_MemoryRead.pUserSrc = pUserSrc;
    cmsg_.input_MemoryRead.readLen = readLen;
    cmsg_.input_MemoryRead.pUserDst = pUserDst;

    ULONG ulRet = 0;
    func_NtQueryIntervalProfile_(COMM::CTRL_CODE, &ulRet);
    if (COMM::CTRL_CODE != ulRet)
    {
        LOG("send control code failed, ret code: 0x%x", ulRet);
        return false;
    }

    return true;
}

bool DriverComm::WriteProcessMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst)
{
    if (!is_init_)
    {
        LOG("no init");
        return false;
    }

    ZeroMemory(&cmsg_, sizeof(COMM::CMSG));
    cmsg_.oper = COMM::Operation::Oper_ProcessMemoryWrite;
    cmsg_.needOutput = false;
    cmsg_.input_MemoryWrite.pUserSrc = pUserSrc;
    cmsg_.input_MemoryWrite.writeLen = writeLen;
    cmsg_.input_MemoryWrite.pid = pid;
    cmsg_.input_MemoryWrite.pUserDst = pUserDst;

    ULONG ulRet = 0;
    func_NtQueryIntervalProfile_(COMM::CTRL_CODE, &ulRet);
    if (COMM::CTRL_CODE != ulRet)
    {
        LOG("send control code failed, ret code: 0x%x", ulRet);
        return false;
    }

    return true;
}

bool DriverComm::GetProcessModuleBase(IN DWORD pid, IN LPCWSTR moduleName, OUT PVOID* pModuleBase, OUT PULONG moduleSize)
{
    if (!is_init_)
    {
        LOG("no init");
        return false;
    }

    ZeroMemory(&cmsg_, sizeof(COMM::CMSG));
    cmsg_.oper = COMM::Operation::Oper_ProcessModuleBase;
    cmsg_.needOutput = true;
    cmsg_.input_ModuleBase.pid = pid;
    wcscpy_s(cmsg_.input_ModuleBase.moduleName, sizeof(cmsg_.input_ModuleBase.moduleName) / sizeof(WCHAR), moduleName);

    ULONG ulRet = 0;
    func_NtQueryIntervalProfile_(COMM::CTRL_CODE, &ulRet);
    if (COMM::CTRL_CODE != ulRet)
    {
        LOG("send control code failed, ret code: 0x%x", ulRet);
        return false;
    }

    *pModuleBase = cmsg_.output_ModuleBase.moduleBase;
    *moduleSize = cmsg_.output_ModuleBase.moduleSize;

    return true;
}
