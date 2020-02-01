#include "hydra.h"

#ifndef _WIN32
#include <time.h>
int32_t sleepn(time_t seconds) {
  struct timespec ts;
  ts.tv_sec = seconds;
  ts.tv_nsec = 0;
  return nanosleep(&ts, NULL);
}
int32_t usleepn(uint64_t milisec) {
  struct timespec ts;
  ts.tv_sec = milisec / 1000;
  ts.tv_nsec = (milisec % 1000) * 1000000L;
  return nanosleep(&ts, NULL);
}

#else

#include <windows.h>
int32_t sleepn(uint32_t seconds) { return SleepEx(milisec * 1000, TRUE); }

int32_t usleepn(uint32_t milisec) { return SleepEx(milisec, TRUE); }
#endif
