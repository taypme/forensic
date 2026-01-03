#ifndef FORENSIC_ARG_PARSER_H
#define FORENSIC_ARG_PARSER_H

#include <stdbool.h>

typedef struct {
    const char *root_arg;
    bool enable_content;
    bool enable_refactor;
    bool enable_sanitize;
    unsigned int ident_mask;
    const char *copy_to_arg;
    bool verbose;
} ParsedArgs;

// Parse command line arguments into ParsedArgs structure
// Returns 0 on success, non-zero on error (and prints usage)
int parse_args(int argc, char **argv, ParsedArgs *out);

#endif

