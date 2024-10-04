#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容

#define DBK_SERVICE_NAME L"RichStuff_Service_Name"
#define DBK_PROCESS_EVENT_NAME L"RichStuff_Process_Event_Name"
#define DBK_THREAD_EVENT_NAME L"RichStuff_Thread_Event_Name"
#define CHEAT_ENGINE_PROCESS_NAME "richstuff-x86"
#define CHEAT_ENGINE_FILE_NAME L"richstuff-x86_64.exe"
#define DBK_DRIVER_NAME L"richstuffk64.sys"
#define MY_DRIVER_NAME L"SafeKProtect.sys"

#define LOG_TAG "GameCheater"

#define __FUNC__ __func__
#define __FILENAME__ \
  (strrchr(__FILE__, '\\') ? (strrchr(__FILE__, '\\') + 1) : __FILE__)

#define LOG(...) \
  tool::log(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)

#define WLOG(...) \
  tool::wlog(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
