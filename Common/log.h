#pragma once

#define LOG(...) \
  tool::log(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)

#define WLOG(...) \
  tool::wlog(LOG_TAG, __FILENAME__, __LINE__, __FUNC__, __VA_ARGS__)
