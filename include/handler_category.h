#ifndef FORENSIC_HANDLER_CATEGORY_H
#define FORENSIC_HANDLER_CATEGORY_H
#include "sweep_context.h"
typedef void (*category_handler_fn)(const SweepContext *ctx, const char *category_dir);
void category_handler_register(const char *category, category_handler_fn fn);
category_handler_fn category_handler_lookup(const char *category);
#endif
