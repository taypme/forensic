#ifndef FORENSIC_PROGRESS_H
#define FORENSIC_PROGRESS_H
#include <stddef.h>
void progress_start(const char *label, size_t total);
void progress_tick(size_t current, size_t total);
void progress_end(void);
#endif
