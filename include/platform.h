#ifndef FORENSIC_PLATFORM_H
#define FORENSIC_PLATFORM_H
#define _POSIX_C_SOURCE 200809L
#ifdef _WIN32
#include <windows.h>
static inline void forensic_sleep_ms(unsigned ms){ Sleep(ms); }
#else
#include <time.h>
static inline void forensic_sleep_ms(unsigned ms){ struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)(ms%1000)*1000000L; nanosleep(&ts,NULL); }
#endif
#endif
