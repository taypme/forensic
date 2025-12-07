#ifndef FORENSIC_FILE_HASH_H
#define FORENSIC_FILE_HASH_H
#include <stddef.h>

int hash_file(const char *path, char *out_hex, size_t out_sz);

#endif
