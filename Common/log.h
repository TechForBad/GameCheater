#pragma once

#define LOG_TAG "GameCheater"

#define __FUNC__ __func__
#define __FILENAME__ \
  (strrchr(__FILE__, '\\') ? (strrchr(__FILE__, '\\') + 1) : __FILE__)

#define LOG(...) \
  tool::log(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)

#define WLOG(...) \
  tool::wlog(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
