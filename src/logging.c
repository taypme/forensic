#include "logging.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

bool g_verbose = false;
static int g_live_active = 0;
static size_t g_live_last_len = 0;
static size_t g_live_width = 120; // cap to avoid line wrapping
static const char *CLR_RESET = "\x1b[0m";
static const char *CLR_YELLOW = "\x1b[33m";
static const char *CLR_GREEN = "\x1b[32m";
static const char *CLR_INFO = "\x1b[94m";

static void clear_live_line(void) {
    if(!g_live_active) return;
    fprintf(stdout, "\r\x1b[2K\r");
    g_live_active = 0;
    g_live_last_len = 0;
    fflush(stdout);
}

static void vlog(FILE *out, const char *prefix, const char *fmt, va_list ap) {
    clear_live_line();
    if(prefix) fputs(prefix, out);
    vfprintf(out, fmt, ap);
    fputc('\n', out);
    fflush(out);
}

void log_set_verbose(bool enable) { g_verbose = enable; }

void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(stdout, "\x1b[94m[info]\x1b[0m ", fmt, ap);
    va_end(ap);
}

void log_sweep_start(const char *label, const char *msg) {
    if(!label || !msg) return;
    char lbl[64];
    snprintf(lbl, sizeof lbl, "%s%s%s", CLR_GREEN, label, CLR_RESET);
    log_info("%s %s", lbl, msg);
}

void log_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(stdout, "[warn] ", fmt, ap);
    va_end(ap);
}

void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(stderr, "[error] ", fmt, ap);
    va_end(ap);
}

void log_debug(const char *fmt, ...) {
    if(!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    vlog(stdout, "[debug] ", fmt, ap);
    va_end(ap);
}

static size_t visible_len(const char *s) {
    size_t len = 0;
    for(size_t i=0; s && s[i]; i++) {
        if(s[i] == '\x1b') { // skip ANSI escape sequences
            while(s[i] && s[i] != 'm') i++;
            continue;
        }
        len++;
    }
    return len;
}

void log_live_status(const char *top, const char *bottom) {
    g_live_active = 1;
    char line[512];
    const char *t = top ? top : "";
    const char *b = bottom ? bottom : "";
    snprintf(line, sizeof line, "%s[info]%s %s%s%s %s%s%s", CLR_INFO, CLR_RESET, CLR_YELLOW, t, CLR_RESET, CLR_YELLOW, b, CLR_RESET);
    size_t disp_len = visible_len(line);
    if(disp_len >= g_live_width) {
        line[g_live_width] = '\0';
        disp_len = g_live_width;
    }
    fprintf(stdout, "\r\x1b[2K\r%s", line);
    g_live_last_len = disp_len;
    fflush(stdout);
}

void log_live_done(void) {
    clear_live_line();
}
