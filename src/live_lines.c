#include "live_lines.h"
#include "logging.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

static char g_live_label[64];
static char g_root[PATH_MAX];

void live_set_root(const char *root) {
    if(!root) { g_root[0] = '\0'; return; }
    snprintf(g_root, sizeof g_root, "%s", root);
}

void live_begin(const char *label) {
    if(!label) label = "";
    snprintf(g_live_label, sizeof g_live_label, "%s", label);
    log_live_status(g_live_label, "");
}

static void to_rel(const char *abs, char *out, size_t out_sz) {
    if(!abs || !out || out_sz==0) return;
    if(g_root[0]) {
        size_t rl = strlen(g_root);
        // Strip trailing slash from root for comparison
        while(rl > 1 && g_root[rl-1] == '/') rl--;
        if(strncmp(abs, g_root, rl)==0 && (abs[rl]=='/' || abs[rl]=='\0')) {
            const char *tail = abs + rl;
            while(*tail=='/') tail++;
            snprintf(out, out_sz, "%s", *tail ? tail : ".");
            return;
        }
    }
    // Fallback: strip leading slashes and make relative-ish
    const char *tail = abs;
    while(*tail=='/') tail++;
    snprintf(out, out_sz, "%s", *tail ? tail : ".");
}

void live_update(const char *item) {
    char buf[PATH_MAX];
    if(item) to_rel(item, buf, sizeof buf); else buf[0]='\0';
    log_live_status(g_live_label, item ? buf : "");
}

void live_end(void) {
    log_live_done();
    g_live_label[0] = '\0';
}
