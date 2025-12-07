#ifndef FORENSIC_HANDLER_EXT_H
#define FORENSIC_HANDLER_EXT_H
#include "sweep_context.h"
typedef void (*ext_handler_fn)(const SweepContext *ctx, const char *path);
void ext_handler_register(const char *key, ext_handler_fn fn);
ext_handler_fn ext_handler_lookup(const char *key);
#endif
