#pragma once

#include <wdm.h>

const int kDebug{ 0 };
const int kInfo{ 1 };
const int kWarn{ 2 };
const int kError{ 3 };

const static char* szLevel[] = { "DEBUG", "INFO", "WARN", "ERROR" };

template <typename... Args>
void log(int _level, const char* _file, int _line, const char* _fun, const char* fmt, Args... args)
{
    KdPrint(("[%s] %s(%d)::%s\n", szLevel[_level], _file, _line, _fun));
    KdPrint((fmt, args...));
    KdPrint(("\n"));
}

#define __FUNC__ __func__
#define __FILENAME__ \
  (strrchr(__FILE__, '\\') ? (strrchr(__FILE__, '\\') + 1) : __FILE__)

#define LOG_DEBUG(...) \
  log(kDebug, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
#define LOG_INFO(...) \
  log(kInfo, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
#define LOG_WARN(...) \
  log(kWarn, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
#define LOG_ERROR(...) \
  log(kError, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
