#include "mem.h"
#include "cleaner.h"
#include "imports.h"
#include "communication.h"

#define NT_QWORD_SIG ("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10")
#define NT_QWORD_MASK ("xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxx")

__int64(__fastcall* origin_NtUserSetGestureConfig)(void* param);

__int64 __fastcall fun_NtUserSetGestureConfig(void* param)
{
    if (reinterpret_cast<cmd_t*>(param)->verification_code != SYSCALL_CODE)
    {
        return origin_NtUserSetGestureConfig(param);
    }

    cmd_t* cmd = reinterpret_cast<cmd_t*>(param);

    switch (cmd->operation)
    {
    case for_test:
    {
        Printf("[+] Called test operation!");
        cmd->success = true;
        break;
    }
    case memory_read:
    {
        Printf("[+] Called read operation!");
        // mem::read_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
        cmd->success = true;
        break;
    }

    case memory_write:
    {
        Printf("[+] Called write operation!");
        // mem::write_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
        cmd->success = true;
        break;
    }

    case module_base:
    {
        Printf("[+] Called base address operation!");
        // cmd->base_address = mem::get_module_base_address(cmd->pid, cmd->module_name);
        cmd->success = true;
        break;
    }

    default:
    {
        Printf("[-] No operation found");
        cmd->success = false;
        break;
    }
    }

    return 0;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	Printf("Enter DriverEntry");

	ULONG win32k_module_size = 0;
	PVOID wink32k_module_base = mem::GetSystemModuleBase("\\SystemRoot\\System32\\win32k.sys", &win32k_module_size);
	if (NULL == wink32k_module_base || 0 == win32k_module_size)
	{
		Printf("Error! Get win32k.sys module base address failed\n");
		return STATUS_UNSUCCESSFUL;
	}

    UINT64 data_ptr = cleaner::FindPattern((UINT64)wink32k_module_base, (UINT64)win32k_module_size, (BYTE*)NT_QWORD_SIG, NT_QWORD_MASK);
	if (NULL == data_ptr)
	{
		Printf("Error! FindPattern failed\n");
		return STATUS_UNSUCCESSFUL;
	}

    UINT64 qword_ptr_derf = (UINT64)(data_ptr);
    qword_ptr_derf = (UINT64)qword_ptr_derf + *(PINT)((PBYTE)qword_ptr_derf + 3) + 7;  // 6
    auto RVA = qword_ptr_derf - (UINT64)wink32k_module_base;
    Printf("data_ptr 0x%llx, qword_ptr_derf 0x%llx, RVA 0x%llx\n", data_ptr, qword_ptr_derf, RVA);

    *(PVOID*)&origin_NtUserSetGestureConfig = InterlockedExchangePointer((PVOID*)qword_ptr_derf, (PVOID)fun_NtUserSetGestureConfig);

	Printf("Leave DriverEntry");
	return STATUS_SUCCESS;
}
