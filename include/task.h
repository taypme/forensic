#ifndef FORENSIC_TASK_H
#define FORENSIC_TASK_H
#include <limits.h>
#include <stddef.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum {
    TASK_DIR,
    TASK_STOP
} TaskType;

typedef struct {
    TaskType type;
    char path[PATH_MAX];
    int depth;
} Task;

#endif // FORENSIC_TASK_H
