#ifndef FORENSIC_UTIL_H
#define FORENSIC_UTIL_H

#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

bool ensure_dir(const char *path, int mode);
bool path_join(const char *a, const char *b, char *out, size_t out_sz);
bool path_basename(const char *path, char *out, size_t out_sz);
bool path_dirname(const char *path, char *out, size_t out_sz);
bool normalize_root(char *path);

#endif
