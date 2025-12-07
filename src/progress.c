#include "progress.h"
#include "logging.h"
#include <stdio.h>
static const char *g_label="";
static size_t g_total=0;
void progress_start(const char *label, size_t total){ g_label=label; g_total=total; log_clear_line(); fprintf(stderr,"[PROGRESS] %s: 0/%zu", g_label, g_total); }
void progress_tick(size_t current, size_t total){ if(total) g_total=total; log_clear_line(); if(g_total) fprintf(stderr,"[PROGRESS] %s: %zu/%zu", g_label, current, g_total); else fprintf(stderr,"[PROGRESS] %s: %zu", g_label, current); }
void progress_end(void){ log_clear_line(); fprintf(stderr,"[PROGRESS] %s: done\n", g_label); }
