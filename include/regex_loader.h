#ifndef FORENSIC_REGEX_LOADER_H
#define FORENSIC_REGEX_LOADER_H

#include <stddef.h>
#include <limits.h>

typedef struct RegexEntry {
    char key[128];
    char **patterns;
    size_t count;
} RegexEntry;

typedef struct RegexRegistry {
    RegexEntry *entries;
    size_t count;
} RegexRegistry;

RegexRegistry *regex_registry_load(const char *root);
void regex_registry_free(RegexRegistry *rr);
const RegexEntry *regex_registry_find(const RegexRegistry *rr, const char *key);

#endif
