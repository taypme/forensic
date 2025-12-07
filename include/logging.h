#ifndef FORENSIC_LOGGING_H
#define FORENSIC_LOGGING_H

#include <stdbool.h>

extern bool g_verbose;

void log_set_verbose(bool enable);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_live_status(const char *top, const char *bottom);
void log_live_done(void);
void log_sweep_start(const char *label, const char *msg);

#endif
