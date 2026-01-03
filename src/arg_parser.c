#include "arg_parser.h"
#include "logging.h"
#include <string.h>
#include <stdlib.h>

static void usage(const char *argv0);

int parse_args(int argc, char **argv, ParsedArgs *out) {
    if(!out) return 1;
    
    // Initialize defaults
    out->root_arg = NULL;
    out->enable_content = true;
    out->enable_refactor = true;
    out->enable_sanitize = false;
    out->ident_mask = 0;
    out->copy_to_arg = NULL;
    out->verbose = false;

    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--verbose")==0) {
            out->verbose = true;
            log_set_verbose(true);
        }
        else if(strcmp(argv[i],"--no-content-analysis")==0) {
            out->enable_content = false;
        }
        else if(strcmp(argv[i],"--no-path-refactor")==0) {
            out->enable_refactor = false;
        }
        else if(strcmp(argv[i],"--sanitize-underscores")==0) {
            out->enable_sanitize = true;
        }
        else if(strncmp(argv[i], "--identifiers=", strlen("--identifiers="))==0) {
            const char *val = argv[i] + strlen("--identifiers=");
            if(val && *val) {
                char *buf = strdup(val);
                if(!buf) return 1; // Out of memory
                char *save=NULL;
                for(char *tok=strtok_r(buf,",",&save); tok; tok=strtok_r(NULL,",",&save)) {
                    if(strcmp(tok,"composer")==0) out->ident_mask |= 1u<<0;
                    else if(strcmp(tok,"symfony")==0) out->ident_mask |= 1u<<1;
                    else if(strcmp(tok,"drupal")==0) out->ident_mask |= 1u<<2;
                    else if(strcmp(tok,"node")==0 || strcmp(tok,"node.js")==0 || strcmp(tok,"nodejs")==0) out->ident_mask |= 1u<<3;
                }
                free(buf);
            }
        }
        else if(strncmp(argv[i], "--structured-data-copy-to=", strlen("--structured-data-copy-to="))==0) {
            out->copy_to_arg = argv[i] + strlen("--structured-data-copy-to=");
            if(!out->copy_to_arg || !*out->copy_to_arg) {
                return 1; // Error: empty path
            }
        }
        else if(strncmp(argv[i], "structured-data-copy-to=", strlen("structured-data-copy-to="))==0) {
            out->copy_to_arg = argv[i] + strlen("structured-data-copy-to=");
            if(!out->copy_to_arg || !*out->copy_to_arg) {
                return 1; // Error: empty path
            }
        }
        else if(argv[i][0]=='-') {
            // Unknown flag
            return 1;
        }
        else {
            // Positional argument (root)
            out->root_arg = argv[i];
        }
    }
    
    // Default root if not provided
    if(!out->root_arg) {
        out->root_arg = ".";
    }
    
    return 0;
}

