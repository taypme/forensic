#ifndef FORENSIC_SWEEP_CONTEXT_H
#define FORENSIC_SWEEP_CONTEXT_H

#include <stdbool.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char root[PATH_MAX];
    int threads;
    long long size_cap_bytes;
    int worker_count;
    char ns[64];
    bool enable_content_analysis;
    bool enable_path_refactor;
    bool enable_patterns;
    bool enable_sanitize_underscores;
    bool enable_rename_files;
    bool enable_identifiers;
    unsigned int ident_mask;
} SweepContext;

#endif
