#ifndef FORENSIC_REDIS_H
#define FORENSIC_REDIS_H
#include <stddef.h>
#include <stdbool.h>

int redis_init(const char *host, int port);
bool redis_available(void);
int redis_set(const char *key, const char *val);
int redis_get(const char *key, char *buf, size_t buflen);
int redis_get_alloc(const char *key, char **out, size_t *out_len);
int redis_append(const char *key, const char *val);
int redis_flushall(void);

#endif // FORENSIC_REDIS_H
