#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>

#include "logging.h"
#include "live_lines.h"
#include "sweep_context.h"
#include "sweep_registry.h"
#include "sweep_services.h"
#include "util.h"

static volatile sig_atomic_t g_sig_stop = 0;
static void on_sigint(int sig) { (void)sig; g_sig_stop = 1; forensic_signal_stop(); }

static void usage(const char *argv0) {
    printf("Usage: %s <root> [--verbose] [--no-content-analysis] [--no-path-refactor] [--sanitize-underscores] [--identifiers=csv]\n", argv0);
    printf("Sweeps:\n");
    printf("  00 identifiers (opt-in via --identifiers): detect composer/symfony/drupal/node and move to identified/\n");
    printf("  01 scan & hash: walk root, hash files\n");
    printf("  02 git archive relocation: move nested .git into .gitarchive\n");
    printf("  03 category creation: ensure category folders\n");
    printf("  04 file movement: route files into categories, dedup\n");
    printf("  05 sanitize underscores: strip _<digits> from names (opt-in via --sanitize-underscores)\n");
    printf("  06 content analysis: lightweight token parsing (skip with --no-content-analysis)\n");
    printf("  07 path hash dedup: deduplicate token hashes\n");
    printf("  08 path refactor: rewrite tokens (skip with --no-path-refactor)\n");
    printf("  09 filename pattern dedup: drop duplicate _N variants\n");
    printf("  10 pattern grouping: group stub variants into <stub>.d/\n");
    printf("  11 empty dir cleanup: final cleanup pass\n");
}

static void derive_namespace(const char *path, char *out, size_t out_sz) {
    if(!path || !out || out_sz==0) return;
    size_t len = strlen(path);
    while(len>0 && path[len-1]=='/') len--;
    const char *end = path + len;
    const char *start = end;
    while(start>path && *(start-1)!='/') start--;
    size_t copy = (size_t)(end - start);
    if(copy==0) copy = 7; // "project"
    if(copy >= out_sz) copy = out_sz - 1;
    if(copy==0) { snprintf(out, out_sz, "project"); return; }
    memcpy(out, start, copy);
    out[copy] = '\0';
}

static bool is_module_root(const char *root) {
    size_t rl = strlen(root);
    if(rl + 10 >= PATH_MAX) return true; // path too long to be safe
    char marker1[PATH_MAX], marker2[PATH_MAX], marker3[PATH_MAX];
    snprintf(marker1,sizeof marker1,"%s/upgrades", root);
    snprintf(marker2,sizeof marker2,"%s/sweeps", root);
    snprintf(marker3,sizeof marker3,"%s/src", root);
    return access(marker1,F_OK)==0 && access(marker2,F_OK)==0 && access(marker3,F_OK)==0;
}

int main(int argc, char **argv) {
    const char *root_arg = NULL;
    bool enable_content = true;
    bool enable_refactor = true;
    bool enable_sanitize = false;
    unsigned int ident_mask = 0;
    bool prewarm = false;
    bool prewarm_only = false;

    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--verbose")==0) log_set_verbose(true);
        else if(strcmp(argv[i],"--no-content-analysis")==0) enable_content = false;
        else if(strcmp(argv[i],"--no-path-refactor")==0) enable_refactor = false;
        else if(strcmp(argv[i],"--sanitize-underscores")==0) enable_sanitize = true;
        else if(strncmp(argv[i], "--identifiers=", strlen("--identifiers="))==0) {
            const char *val = argv[i] + strlen("--identifiers=");
            if(val && *val) {
                char *buf = strdup(val);
                if(!buf) { log_error("oom parsing identifiers"); return 1; }
                char *save=NULL;
                for(char *tok=strtok_r(buf,",",&save); tok; tok=strtok_r(NULL,",",&save)) {
                    if(strcmp(tok,"composer")==0) ident_mask |= 1u<<0;
                    else if(strcmp(tok,"symfony")==0) ident_mask |= 1u<<1;
                    else if(strcmp(tok,"drupal")==0) ident_mask |= 1u<<2;
                    else if(strcmp(tok,"node")==0 || strcmp(tok,"node.js")==0 || strcmp(tok,"nodejs")==0) ident_mask |= 1u<<3;
                }
                free(buf);
            }
        }
        else if(argv[i][0]=='-') { usage(argv[0]); return 1; }
        else root_arg = argv[i];
    }
    if(!root_arg) { root_arg = "."; }

    char root[PATH_MAX];
    if(!realpath(root_arg, root)) {
        log_error("unable to resolve root: %s", root_arg);
        return 1;
    }
    normalize_root(root);
    if(is_module_root(root)) {
        log_error("refusing to run inside module directory (%s)", root);
        return 2;
    }
    live_set_root(root);

    int threads = sysconf(_SC_NPROCESSORS_ONLN);
    if(threads < 1) threads = 4;
    if(threads > 12) threads = 12;

    signal(SIGINT, on_sigint);

    SweepContext ctx;
    memset(&ctx, 0, sizeof ctx);
    snprintf(ctx.root, sizeof ctx.root, "%s", root);
    ctx.threads = threads;
    ctx.worker_count = threads;
    ctx.size_cap_bytes = 0;
    ctx.svc = &g_sweep_services_default;
    ctx.enable_content_analysis = enable_content;
    ctx.enable_path_refactor = enable_refactor;
    ctx.enable_patterns = true;
    ctx.enable_sanitize_underscores = enable_sanitize;
    ctx.enable_identifiers = ident_mask != 0;
    ctx.ident_mask = ident_mask;
    derive_namespace(root, ctx.ns, sizeof ctx.ns);

    setenv("FORENSIC_ROOT", ctx.root, 1);
    log_info("forensic initialized root=%s threads=%d verbose=%s", ctx.root, ctx.threads, g_verbose?"yes":"no");

    (void)prewarm; (void)prewarm_only;

    int rc = run_all_sweeps(&ctx);
    if(rc!=0) {
        log_error("run failed rc=%d", rc);
        return rc;
    }
    if(g_sig_stop) {
        log_warn("stopped by signal");
    }
    return 0;
}
