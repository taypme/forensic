#ifndef FORENSIC_HANDLERS_H
#define FORENSIC_HANDLERS_H
#include "sweep_context.h"
#include "types.h"

typedef void (*handler_pre_fn)(SweepId id, SweepContext *ctx);
typedef void (*handler_post_fn)(SweepId id, SweepContext *ctx, int rc);

typedef struct HandlerHook {
    const char *name;
    handler_pre_fn pre;
    handler_post_fn post;
    struct HandlerHook *next;
} HandlerHook;

void handler_register(const char *name, handler_pre_fn pre, handler_post_fn post);
const HandlerHook* handler_registry_head(void);
void handler_run_pre(SweepId id, SweepContext *ctx);
void handler_run_post(SweepId id, SweepContext *ctx, int rc);

#endif
