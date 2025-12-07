#ifndef FORENSIC_WORKERS_H
#define FORENSIC_WORKERS_H

#include <stddef.h>
#include <sys/stat.h>
#include <stdbool.h>

typedef bool (*forensic_dir_filter_fn)(const char *path, const struct stat *st, int depth, void *userdata);
typedef bool (*forensic_file_filter_fn)(const char *path, const struct stat *st, int depth, void *userdata);

int scan_directory_parallel(const char *root, int threads, forensic_dir_filter_fn dir_filter, forensic_file_filter_fn file_filter, void *userdata, char ***out_files, size_t *out_count, size_t *out_dirs);

#endif
