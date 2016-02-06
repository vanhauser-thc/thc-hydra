#include "hydra.h"

#ifndef _WIN32
#include <time.h>
int sleepn(time_t seconds)
{
	struct timespec ts;
	ts.tv_sec = seconds;
	ts.tv_nsec = 0;
   return nanosleep(&ts, NULL);
}
int usleepn(long int milisec) {
	struct timespec ts;
	ts.tv_sec = milisec / 1000;
	ts.tv_nsec = (milisec % 1000) * 1000000L;
	return nanosleep(&ts, NULL);
}

#else

#include <windows.h>
int sleepn(unsigned int seconds) 
{
 return SleepEx(milisec*1000,TRUE);
}

int usleepn(unsigned int milisec) 
{
 return SleepEx(milisec,TRUE);
}
#endif
