#ifndef FORENSIC_SHA256_H
#define FORENSIC_SHA256_H

#include <stddef.h>

int sha256_file(const char *path, char *out_hex, size_t out_hex_sz);

#endif
