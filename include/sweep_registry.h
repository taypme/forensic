#ifndef FORENSIC_SWEEP_REGISTRY_H
#define FORENSIC_SWEEP_REGISTRY_H

#include <stddef.h>
#include "types.h"
#include "sweep_context.h"

typedef int (*SweepFn)(SweepContext *ctx);

typedef struct {
    SweepId id;
    const char *name;
    SweepFn run;
} Sweep;

size_t register_sweeps(Sweep *out, size_t max);
int run_all_sweeps(SweepContext *ctx);
int run_prewarm(SweepContext *ctx);
int forensic_should_stop(void);
void forensic_signal_stop(void);

#endif
