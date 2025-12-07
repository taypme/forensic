#ifndef FORENSIC_SWEEP_SERVICES_H
#define FORENSIC_SWEEP_SERVICES_H

#include <stddef.h>

struct SweepContext;

typedef struct SweepServices {
    void (*log_info)(const char *fmt, ...);
    void (*log_warn)(const char *fmt, ...);
    void (*log_error)(const char *fmt, ...);
    void (*log_debug)(const char *fmt, ...);
    void (*log_live_status)(const char *top, const char *bottom);
    void (*log_live_done)(void);
    int  (*hash_file)(const char *path, char *out_hex, size_t out_sz);
    int  (*hash_bytes)(const unsigned char *data, size_t len, char *out_hex, size_t out_sz);
    int  (*rename_fn)(const char *src, const char *dst);
    int  (*unlink_fn)(const char *path);
    int  (*ensure_dir)(const char *path, int mode);
    int  (*path_join)(const char *a, const char *b, char *out, size_t out_sz);
} SweepServices;

extern const SweepServices g_sweep_services_default;

#endif
