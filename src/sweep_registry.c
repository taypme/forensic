#define _GNU_SOURCE
#include "sweep_registry.h"
#include "logging.h"
#include "sha256.h"
#include "sweep_services.h"
#include "util.h"
#include "workers.h"
#include <time.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <stdatomic.h>
#include <ctype.h>
#include <errno.h>

#define CLR_RESET "\x1b[0m"
#define CLR_CYAN  "\x1b[36m"
#define CLR_GREEN "\x1b[32m"
#define CLR_MAGENTA "\x1b[35m"

#define SVC_PTR(ctx) ((ctx) ? (ctx)->svc : NULL)
#define SVC_HAS(ctx, member) (SVC_PTR(ctx) && SVC_PTR(ctx)->member)
#define SVC_LOG_INFO(ctx, fmt, ...) do { if(SVC_HAS(ctx, log_info)) SVC_PTR(ctx)->log_info(fmt, ##__VA_ARGS__); else log_info(fmt, ##__VA_ARGS__); } while(0)
#define SVC_LOG_WARN(ctx, fmt, ...) do { if(SVC_HAS(ctx, log_warn)) SVC_PTR(ctx)->log_warn(fmt, ##__VA_ARGS__); else log_warn(fmt, ##__VA_ARGS__); } while(0)
#define SVC_LOG_ERROR(ctx, fmt, ...) do { if(SVC_HAS(ctx, log_error)) SVC_PTR(ctx)->log_error(fmt, ##__VA_ARGS__); else log_error(fmt, ##__VA_ARGS__); } while(0)
#define SVC_LOG_DEBUG(ctx, fmt, ...) do { if(SVC_HAS(ctx, log_debug)) SVC_PTR(ctx)->log_debug(fmt, ##__VA_ARGS__); else log_debug(fmt, ##__VA_ARGS__); } while(0)
#define SVC_LOG_LIVE_STATUS(ctx, top, bottom) do { if(SVC_HAS(ctx, log_live_status)) SVC_PTR(ctx)->log_live_status(top, bottom); else log_live_status(top, bottom); } while(0)
#define SVC_LOG_LIVE_DONE(ctx) do { if(SVC_HAS(ctx, log_live_done)) SVC_PTR(ctx)->log_live_done(); else log_live_done(); } while(0)

static int svc_hash_file_ctx(const SweepContext *ctx, const char *path, char *out, size_t out_sz) {
    if(SVC_HAS(ctx, hash_file)) return SVC_PTR(ctx)->hash_file(path, out, out_sz);
    return sha256_file(path, out, out_sz);
}

static int svc_hash_bytes_ctx(const SweepContext *ctx, const unsigned char *data, size_t len, char *out, size_t out_sz) {
    if(SVC_HAS(ctx, hash_bytes)) return SVC_PTR(ctx)->hash_bytes(data, len, out, out_sz);
    return -1;
}

static int svc_rename_ctx(const SweepContext *ctx, const char *src, const char *dst) {
    if(SVC_HAS(ctx, rename_fn)) return SVC_PTR(ctx)->rename_fn(src, dst);
    return rename(src, dst);
}

static int svc_unlink_ctx(const SweepContext *ctx, const char *path) {
    if(SVC_HAS(ctx, unlink_fn)) return SVC_PTR(ctx)->unlink_fn(path);
    return unlink(path);
}

static int svc_ensure_dir_ctx(const SweepContext *ctx, const char *path, int mode) {
    if(SVC_HAS(ctx, ensure_dir)) return SVC_PTR(ctx)->ensure_dir(path, mode);
    return ensure_dir(path, mode) ? 0 : -1;
}

static int svc_path_join_ctx(const SweepContext *ctx, const char *a, const char *b, char *out, size_t out_sz) {
    if(SVC_HAS(ctx, path_join)) return SVC_PTR(ctx)->path_join(a, b, out, out_sz);
    return path_join(a, b, out, out_sz) ? 0 : -1;
}

#define IDENT_COMPOSER (1u<<0)
#define IDENT_SYMFONY  (1u<<1)
#define IDENT_DRUPAL   (1u<<2)
#define IDENT_NODE     (1u<<3)

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} StrList;

typedef struct {
    char path[PATH_MAX];
    char key[32];
    char name[128];
} IdentHit;

static int read_file_limited(const char *path, size_t max_bytes, char **out_buf, size_t *out_len);
static void sanitize_live_path(const SweepContext *ctx, const char *path, char *out, size_t out_sz);
static void rel_for_log(const SweepContext *ctx, const char *abs, char *out, size_t out_sz);
static void dedupe_segments(char *s, size_t cap);
static bool append_hit(IdentHit **hits, size_t *count, size_t *cap, const char *path, const char *key, const char *name);
static size_t common_prefix_segments(const IdentHit *hits, size_t count, const char *key);
static size_t common_suffix_segments(const IdentHit *hits, size_t count, const char *key);
static void trim_segments(char *name, size_t drop_prefix, size_t drop_suffix);

static void sweep_label(int id, char *out, size_t out_sz) {
    if(!out || out_sz==0) return;
    snprintf(out, out_sz, "[sweep %02d]", id);
}

static double elapsed_seconds(const struct timespec *start, const struct timespec *end) {
    if(!start || !end) return 0.0;
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    if(nsec < 0) { sec -= 1; nsec += 1000000000L; }
    return (double)sec + (double)nsec / 1e9;
}

static void format_duration(double seconds, bool allow_seconds, char *out, size_t out_sz) {
    if(!out || out_sz==0) return;
    if(allow_seconds && seconds < 10.0) {
        snprintf(out, out_sz, "%.1fs", seconds);
    } else {
        double minutes = seconds / 60.0;
        snprintf(out, out_sz, "%.1fm", minutes);
    }
}

static void log_timing_summary(const SweepContext *ctx, const Sweep *sweeps, const double *durations, const bool *ran, size_t count, double total_seconds) {
    if(!sweeps || !durations || !ran) return;
    SVC_LOG_INFO(ctx, "%sSweep timing summary%s", CLR_MAGENTA, CLR_RESET);
    for(size_t i=0;i<count;i++) {
        if(!ran[i]) continue;
        char lbl[32]; sweep_label(sweeps[i].id, lbl, sizeof lbl);
        char dur[32]; format_duration(durations[i], true, dur, sizeof dur);
        SVC_LOG_INFO(ctx, "  %s%-18s%s %-24s %s%s%s", CLR_CYAN, lbl, CLR_RESET, sweeps[i].name, CLR_GREEN, dur, CLR_RESET);
    }
    char total[32]; format_duration(total_seconds, false, total, sizeof total);
    SVC_LOG_INFO(ctx, "%sTotal elapsed%s %s%s%s", CLR_MAGENTA, CLR_RESET, CLR_GREEN, total, CLR_RESET);
}

static void strlist_init(StrList *sl) {
    sl->items = NULL; sl->count = sl->cap = 0;
}

static void strlist_free(StrList *sl) {
    if(!sl) return;
    for(size_t i=0;i<sl->count;i++) free(sl->items[i]);
    free(sl->items);
    sl->items = NULL; sl->count = sl->cap = 0;
}

static bool strlist_append(StrList *sl, const char *s) {
    if(!sl || !s) return false;
    if(sl->count == sl->cap) {
        size_t nc = sl->cap ? sl->cap * 2 : 64;
        char **tmp = realloc(sl->items, nc * sizeof(char*));
        if(!tmp) return false;
        sl->items = tmp;
        sl->cap = nc;
    }
    sl->items[sl->count] = strdup(s);
    if(!sl->items[sl->count]) return false;
    sl->count++;
    return true;
}

static int cmp_str(const void *a, const void *b) {
    const char *sa = *(const char * const*)a;
    const char *sb = *(const char * const*)b;
    return strcmp(sa, sb);
}

static void strlist_dedupe(StrList *sl) {
    if(!sl || sl->count < 2) return;
    qsort(sl->items, sl->count, sizeof(char*), cmp_str);
    size_t w = 0;
    for(size_t r=0;r<sl->count;r++) {
        if(w==0 || strcmp(sl->items[r], sl->items[w-1])!=0) {
            sl->items[w++] = sl->items[r];
        } else {
            free(sl->items[r]);
        }
    }
    sl->count = w;
}

static atomic_int g_stop = ATOMIC_VAR_INIT(0);
int forensic_should_stop(void) { return atomic_load(&g_stop); }
void forensic_signal_stop(void) { atomic_store(&g_stop, 1); }

// ---------- Identifier Sweep ----------

static bool has_child(const char *dir, const char *name) {
    char path[PATH_MAX];
    if(!path_join(dir, name, path, sizeof path)) return false;
    return access(path, F_OK) == 0;
}

static bool read_small_json(const char *path, char **out, size_t *len) {
    return read_file_limited(path, 128 * 1024, out, len) == 0;
}

static bool has_drupal_root(const char *dir) {
    if(!dir) return false;
    const char *core_paths[] = {
        "core/lib/Drupal.php",
        "web/core/lib/Drupal.php",
        "docroot/core/lib/Drupal.php",
        NULL
    };
    for(size_t i=0; core_paths[i]; i++) {
        if(has_child(dir, core_paths[i])) return true;
    }
    const char *tree_markers[][4] = {
        {"core", "modules", "profiles", "sites"},
        {"web/core", "web/modules", "web/profiles", "web/sites"},
        {"docroot/core", "docroot/modules", "docroot/profiles", "docroot/sites"},
    };
    for(size_t i=0; i<sizeof tree_markers/sizeof tree_markers[0]; i++) {
        if(has_child(dir, tree_markers[i][0]) &&
           has_child(dir, tree_markers[i][1]) &&
           has_child(dir, tree_markers[i][2]) &&
           has_child(dir, tree_markers[i][3])) {
            return true;
        }
    }
    return false;
}

static bool extract_json_name(const char *buf, const char *field, char *out, size_t out_sz) {
    if(!buf || !field || !out || out_sz==0) return false;
    const char *p = strstr(buf, field);
    if(!p) return false;
    p = strchr(p, ':');
    if(!p) return false;
    while(*p && (*p==' ' || *p=='\t' || *p==':')) p++;
    if(*p != '\"') return false;
    p++;
    size_t pos=0;
    while(*p && *p!='\"' && pos+1<out_sz) {
        out[pos++] = *p++;
    }
    out[pos] = '\0';
    return pos>0;
}

static void safe_name(const char *src, char *out, size_t out_sz) {
    if(!src || !out || out_sz==0) return;
    size_t pos=0;
    for(size_t i=0; src[i] && pos+1<out_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if(isalnum(c) || c=='-' || c=='_') out[pos++] = (char)c;
        else if(c=='/' || c=='\\' || c==' ') out[pos++]='-';
    }
    if(pos==0) { snprintf(out, out_sz, "unknown"); return; }
    out[pos] = '\0';
    dedupe_segments(out, out_sz);
}

static void dedupe_segments(char *s, size_t cap) {
    if(!s || !*s || cap==0) return;
    char *parts[256];
    size_t part_count = 0;
    for(char *p=s; *p && part_count < (sizeof parts / sizeof parts[0]); ) {
        parts[part_count++] = p;
        while(*p && *p!='-') p++;
        if(*p=='-') { *p='\0'; p++; }
    }
    for(size_t i=part_count; i-- > 0; ) {
        for(size_t j=0; j<i; j++) {
            if(strcmp(parts[i], parts[j])==0) { parts[i][0]='\0'; break; }
        }
    }
    char tmp[256];
    size_t pos=0;
    for(size_t i=0; i<part_count && pos+1<sizeof(tmp); i++) {
        if(parts[i][0]=='\0') continue;
        size_t len = strlen(parts[i]);
        if(len==0) continue;
        if(pos>0 && pos+1<sizeof(tmp)) tmp[pos++]='-';
        if(pos+len >= sizeof(tmp)) len = sizeof(tmp)-pos-1;
        memcpy(tmp+pos, parts[i], len);
        pos += len;
    }
    tmp[pos]='\0';
    const char *src = pos ? tmp : "unknown";
    snprintf(s, cap, "%.*s", (int)(cap>0 ? cap-1 : 0), src);
}

static bool append_hit(IdentHit **hits, size_t *count, size_t *cap, const char *path, const char *key, const char *name) {
    if(!hits || !count || !cap || !path || !key || !name) return false;
    if(*count == *cap) {
        size_t nc = *cap ? *cap * 2 : 32;
        IdentHit *tmp = realloc(*hits, nc * sizeof(IdentHit));
        if(!tmp) return false;
        *hits = tmp;
        *cap = nc;
    }
    IdentHit *h = &(*hits)[(*count)++];
    snprintf(h->path, sizeof h->path, "%s", path);
    snprintf(h->key, sizeof h->key, "%s", key);
    snprintf(h->name, sizeof h->name, "%s", name);
    return true;
}

static size_t segment_count(const char *name) {
    if(!name || !*name) return 0;
    size_t cnt=1;
    for(const char *p=name; *p; p++) if(*p=='-') cnt++;
    return cnt;
}

static bool segment_at(const char *name, size_t idx_from_start, size_t idx_from_end, bool use_end, char *out, size_t out_sz) {
    if(!name || !out || out_sz==0) return false;
    size_t total = segment_count(name);
    if(total==0) return false;
    size_t idx = use_end ? (total - 1 - idx_from_end) : idx_from_start;
    if(idx >= total) return false;
    size_t cur=0;
    const char *p = name;
    const char *seg_start = p;
    for(; *p && cur<idx; p++) {
        if(*p=='-') { cur++; seg_start = p+1; }
    }
    const char *seg_end = seg_start;
    while(*seg_end && *seg_end!='-') seg_end++;
    size_t len = (size_t)(seg_end - seg_start);
    if(len >= out_sz) len = out_sz - 1;
    memcpy(out, seg_start, len);
    out[len]='\0';
    return true;
}

static size_t common_prefix_segments(const IdentHit *hits, size_t count, const char *key) {
    if(!hits || count==0 || !key) return 0;
    size_t prefix=0;
    while(1) {
        char seg[128];
        bool got=false;
        for(size_t i=0;i<count;i++) {
            if(strcmp(hits[i].key, key)!=0) continue;
            if(!segment_at(hits[i].name, prefix, 0, false, seg, sizeof seg)) return prefix;
            got=true; break;
        }
        if(!got) return 0;
        for(size_t j=0;j<count;j++) {
            if(strcmp(hits[j].key, key)!=0) continue;
            char other[128];
            if(!segment_at(hits[j].name, prefix, 0, false, other, sizeof other)) return prefix;
            if(strcmp(other, seg)!=0) return prefix;
        }
        prefix++;
    }
}

static size_t common_suffix_segments(const IdentHit *hits, size_t count, const char *key) {
    if(!hits || count==0 || !key) return 0;
    size_t suffix=0;
    while(1) {
        char seg[128];
        bool got=false;
        for(size_t i=0;i<count;i++) {
            if(strcmp(hits[i].key, key)!=0) continue;
            if(!segment_at(hits[i].name, 0, suffix, true, seg, sizeof seg)) return suffix;
            got=true; break;
        }
        if(!got) return 0;
        for(size_t j=0;j<count;j++) {
            if(strcmp(hits[j].key, key)!=0) continue;
            char other[128];
            if(!segment_at(hits[j].name, 0, suffix, true, other, sizeof other)) return suffix;
            if(strcmp(other, seg)!=0) return suffix;
        }
        suffix++;
    }
}

static void trim_segments(char *name, size_t drop_prefix, size_t drop_suffix) {
    if(!name || !*name) return;
    char tmp[128];
    snprintf(tmp, sizeof tmp, "%s", name);
    char *segs[64];
    size_t count=0;
    char *save=NULL;
    for(char *tok=strtok_r(tmp,"-",&save); tok && count<64; tok=strtok_r(NULL,"-",&save)) {
        segs[count++] = tok;
    }
    if(count==0) return;
    size_t start = drop_prefix < count ? drop_prefix : count;
    size_t end_drop = drop_suffix < count ? drop_suffix : count;
    size_t end = count > end_drop ? count - end_drop : start;
    if(start >= end) return;
    size_t pos=0;
    for(size_t i=start; i<end && pos+1<sizeof(tmp); i++) {
        size_t len = strlen(segs[i]);
        if(pos>0 && pos+1<sizeof(tmp)) tmp[pos++]='-';
        if(pos+len >= sizeof(tmp)) len = sizeof(tmp)-pos-1;
        memcpy(tmp+pos, segs[i], len);
        pos += len;
    }
    tmp[pos]='\0';
    snprintf(name, 128, "%s", tmp);
}

typedef struct {
    const char *dir;
    const char *composer_buf;
    const char *package_buf;
    bool has_composer;
    bool has_pkg;
    bool drupal_app;
    char composer_name[128];
    char package_name[128];
    const SweepContext *ctx;
} IdentifierMeta;

static bool plugin_detect_drupal(const IdentifierMeta *m, char *key, size_t key_sz, char *name, size_t name_sz) {
    if(!m || !m->drupal_app) return false;
    snprintf(key, key_sz, "drupal");
    char rel[PATH_MAX];
    rel_for_log(m->ctx, m->dir, rel, sizeof rel);
    const char *label = m->composer_name[0] ? m->composer_name : (rel[0] ? rel : m->dir);
    safe_name(label, name, name_sz);
    return true;
}

static bool plugin_detect_symfony(const IdentifierMeta *m, char *key, size_t key_sz, char *name, size_t name_sz) {
    if(!m || m->drupal_app || !m->has_composer) return false;
    bool symfony_pkg = m->composer_buf &&
        (strstr(m->composer_buf, "\"symfony/framework-bundle\"") ||
         strstr(m->composer_buf, "\"symfony/symfony\"") ||
         strstr(m->composer_buf, "\"symfony/http-kernel\"") ||
         strstr(m->composer_buf, "\"symfony/console\"") ||
         strstr(m->composer_buf, "\"symfony/routing\""));
    bool symfony_console = has_child(m->dir, "bin/console");
    bool symfony_config = has_child(m->dir, "config") || has_child(m->dir, "app/config");
    int signals = (symfony_pkg?1:0) + (symfony_console?1:0) + (symfony_config?1:0);
    if(signals < 2) return false;
    snprintf(key, key_sz, "symfony");
    safe_name(m->composer_name[0]?m->composer_name:m->dir, name, name_sz);
    return true;
}

static bool plugin_detect_composer(const IdentifierMeta *m, char *key, size_t key_sz, char *name, size_t name_sz) {
    if(!m || !m->has_composer || m->drupal_app) return false;
    snprintf(key, key_sz, "composer");
    safe_name(m->composer_name[0]?m->composer_name:m->dir, name, name_sz);
    return true;
}

static bool plugin_detect_node(const IdentifierMeta *m, char *key, size_t key_sz, char *name, size_t name_sz) {
    if(!m || !m->has_pkg || m->drupal_app) return false;
    snprintf(key, key_sz, "node");
    safe_name(m->package_name[0]?m->package_name:m->dir, name, name_sz);
    return true;
}

typedef struct {
    const char *key;
    unsigned int bit;
    bool (*detect)(const IdentifierMeta *, char *, size_t, char *, size_t);
} IdentifierPlugin;

static const IdentifierPlugin g_identifier_plugins[] = {
    {"drupal", IDENT_DRUPAL, plugin_detect_drupal},
    {"symfony", IDENT_SYMFONY, plugin_detect_symfony},
    {"composer", IDENT_COMPOSER, plugin_detect_composer},
    {"node", IDENT_NODE, plugin_detect_node},
};

static bool detect_identifier(const SweepContext *ctx, unsigned int mask, const char *dir, char *key, size_t key_sz, char *name, size_t name_sz) {
    if(!dir || !key || !name) return false;
    key[0]=name[0]='\0';
    bool has_composer = (mask & (IDENT_COMPOSER|IDENT_SYMFONY|IDENT_DRUPAL)) && (has_child(dir, "composer.json") || has_child(dir, "composer.lock"));
    bool has_pkg = (mask & IDENT_NODE) && (has_child(dir, "package.json") || has_child(dir, "package-lock.json") || has_child(dir, "yarn.lock"));
    char *composer_buf=NULL, *package_buf=NULL;
    size_t c_len=0, p_len=0;
    char composer_name[128]="", package_name[128]="";
    if(has_composer) {
        char path[PATH_MAX];
        if(path_join(dir,"composer.json",path,sizeof path) && read_small_json(path,&composer_buf,&c_len)) {
            extract_json_name(composer_buf, "\"name\"", composer_name, sizeof composer_name);
        }
    }
    if(has_pkg) {
        char path[PATH_MAX];
        if(path_join(dir,"package.json",path,sizeof path) && read_small_json(path,&package_buf,&p_len)) {
            extract_json_name(package_buf, "\"name\"", package_name, sizeof package_name);
        }
    }
    IdentifierMeta meta = {
        .dir = dir,
        .composer_buf = composer_buf,
        .package_buf = package_buf,
        .has_composer = has_composer,
        .has_pkg = has_pkg,
        .drupal_app = false,
        .ctx = ctx,
    };
    snprintf(meta.composer_name, sizeof meta.composer_name, "%s", composer_name);
    snprintf(meta.package_name, sizeof meta.package_name, "%s", package_name);
    {
        bool looks_like_root = has_drupal_root(dir);
        bool mentions_core = composer_buf && strstr(composer_buf, "drupal/core");
        bool is_component = composer_buf &&
            (strstr(composer_buf, "drupal-module") || strstr(composer_buf, "drupal-theme") || strstr(composer_buf, "drupal-profile"));
        if((looks_like_root || mentions_core) && !is_component) meta.drupal_app = true;
    }

    bool found=false;
    for(size_t i=0;i<sizeof(g_identifier_plugins)/sizeof(g_identifier_plugins[0]);i++) {
        const IdentifierPlugin *pl = &g_identifier_plugins[i];
        if((mask & pl->bit)==0) continue;
        if(pl->detect && pl->detect(&meta, key, key_sz, name, name_sz)) { found=true; break; }
    }

    if(composer_buf) free(composer_buf);
    if(package_buf) free(package_buf);
    return found;
}

static bool move_identified(const SweepContext *ctx, const char *dir, const char *key, const char *name) {
    if(!ctx || !dir || !key || !name) return false;
    if(strcmp(dir, ctx->root)==0) {
        SVC_LOG_WARN(ctx, "identifiers: refusing to move root directory");
        return false;
    }
    char target[PATH_MAX];
    if(svc_path_join_ctx(ctx, ctx->root, "identified", target, sizeof target)!=0) return false;
    svc_ensure_dir_ctx(ctx, target, 0755);
    size_t len = strlen(target);
    if(len + strlen(key) + strlen(name) + 3 >= sizeof target) return false;
    snprintf(target + len, sizeof target - len, "/%s", key);
    svc_ensure_dir_ctx(ctx, target, 0755);
    len = strlen(target);
    snprintf(target + len, sizeof target - len, "/%s", name);
    char dest[PATH_MAX];
    bool moved = false;
    for(int attempt=0; attempt<50; attempt++) {
        if(attempt==0) {
            snprintf(dest, sizeof dest, "%s", target);
        } else {
            if(strlen(target) + 16 >= sizeof dest) break;
            snprintf(dest, sizeof dest, "%s-%d", target, attempt);
        }
        if(svc_rename_ctx(ctx, dir, dest)==0) {
            moved = true;
            break;
        }
        if(errno!=EEXIST && errno!=ENOTEMPTY) break;
    }
    if(!moved) {
        SVC_LOG_WARN(ctx, "identifiers: rename failed %s -> %s (%s)", dir, target, strerror(errno));
        return false;
    }
    char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
    char lbl[16]; sweep_label(SWEEP_IDENTIFIERS, lbl, sizeof lbl);
    SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
    return true;
}

static size_t sweep_identifier_pass(SweepContext *ctx, unsigned int mask, bool trim_drupal) {
    if(mask==0) return 0;
    StrList queue; strlist_init(&queue);
    strlist_append(&queue, ctx->root);
    IdentHit *hits = NULL; size_t hit_count=0, hit_cap=0;
    size_t identified = 0;
    for(size_t idx=0; idx<queue.count; idx++) {
        const char *cur = queue.items[idx];
        const char *base = strrchr(cur, '/');
        base = base ? base + 1 : cur;
        if(strcmp(base,".")==0 || strcmp(base,"..")==0) continue;
        if(strcmp(base,".git")==0 || strcmp(base,".gitarchive")==0 || strcmp(base,"identified")==0 || strcmp(base,"node_modules")==0 || strcmp(base,"vendor")==0) continue;
        if(strcmp(cur, ctx->root)!=0) {
            char key[32], name[128];
            if(detect_identifier(ctx, mask, cur, key, sizeof key, name, sizeof name)) {
                append_hit(&hits, &hit_count, &hit_cap, cur, key, name);
                continue;
            }
        }
        DIR *d = opendir(cur);
        if(!d) continue;
        struct dirent *ent;
        while((ent = readdir(d))) {
            if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
            char path[PATH_MAX];
            if(!path_join(cur, ent->d_name, path, sizeof path)) continue;
            struct stat st;
            if(stat(path, &st)!=0) continue;
            if(S_ISDIR(st.st_mode)) {
                strlist_append(&queue, path);
            }
        }
        closedir(d);
    }

    if(trim_drupal && hit_count>0) {
        size_t drupal_prefix = common_prefix_segments(hits, hit_count, "drupal");
        size_t drupal_suffix = common_suffix_segments(hits, hit_count, "drupal");
        for(size_t i=0;i<hit_count;i++) {
            if(strcmp(hits[i].key, "drupal")==0) {
                if(drupal_prefix>0) trim_segments(hits[i].name, drupal_prefix, 0);
                if(drupal_suffix>0) trim_segments(hits[i].name, 0, drupal_suffix);
                if(hits[i].name[0]=='\0') snprintf(hits[i].name, sizeof hits[i].name, "drupal");
            }
        }
    }

    for(size_t i=0;i<hit_count;i++) {
        if(move_identified(ctx, hits[i].path, hits[i].key, hits[i].name)) identified++;
    }
    free(hits);
    strlist_free(&queue);
    return identified;
}

static int sweep_identifiers(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_IDENTIFIERS, lbl, sizeof lbl);
    log_sweep_start(lbl, "identifiers starting");
    if(!ctx->enable_identifiers || ctx->ident_mask==0) {
        SVC_LOG_INFO(ctx, "%s skipped (disabled)", lbl);
        return 0;
    }
    size_t identified = 0;
    if(ctx->ident_mask & IDENT_DRUPAL) {
        identified += sweep_identifier_pass(ctx, IDENT_DRUPAL, true);
    }
    unsigned int symfony_mask = ctx->ident_mask & IDENT_SYMFONY;
    if(symfony_mask) {
        identified += sweep_identifier_pass(ctx, symfony_mask, false);
    }
    unsigned int composer_mask = ctx->ident_mask & IDENT_COMPOSER;
    if(composer_mask) {
        identified += sweep_identifier_pass(ctx, composer_mask, false);
    }
    unsigned int remaining = ctx->ident_mask & ~(IDENT_DRUPAL|IDENT_COMPOSER|IDENT_SYMFONY);
    if(remaining) {
        identified += sweep_identifier_pass(ctx, remaining, false);
    }
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s identified=%zu", lbl, identified);
    return 0;
}


static int read_file_limited(const char *path, size_t max_bytes, char **out_buf, size_t *out_len) {
    if(!out_buf) return -1;
    *out_buf = NULL;
    FILE *f = fopen(path, "rb");
    if(!f) return -1;
    if(fseek(f, 0, SEEK_END)!=0) { fclose(f); return -1; }
    long sz = ftell(f);
    if(sz < 0) { fclose(f); return -1; }
    if((size_t)sz > max_bytes) { fclose(f); return 1; }
    if(fseek(f, 0, SEEK_SET)!=0) { fclose(f); return -1; }
    size_t len = (size_t)sz;
    char *buf = (char*)malloc(len + 1);
    if(!buf) { fclose(f); return -1; }
    size_t r = fread(buf,1,len,f);
    fclose(f);
    if(r != len) { free(buf); return -1; }
    buf[len] = '\0';
    *out_buf = buf;
    if(out_len) *out_len = len;
    return 0;
}

static void rel_for_log(const SweepContext *ctx, const char *abs, char *out, size_t out_sz) {
    if(!ctx || !abs || !out || out_sz==0) return;
    const char *tail = abs;
    size_t rl = strlen(ctx->root);
    if(strncmp(abs, ctx->root, rl)==0 && (abs[rl]=='/' || abs[rl]=='\0')) {
        tail = abs + rl;
        while(*tail=='/') tail++;
    } else {
        while(*tail=='/') tail++;
    }
    if(!*tail) { snprintf(out, out_sz, "."); return; }
    snprintf(out, out_sz, "%s", tail);
}

static void sanitize_live_path(const SweepContext *ctx, const char *path, char *out, size_t out_sz) {
    if(!path || !out || out_sz==0) return;
    // 1) Try direct root stripping.
    rel_for_log(ctx, path, out, out_sz);
    if(out[0] && out[0] != '/') return;
    // 2) Try resolved absolute path.
    char real[PATH_MAX];
    if(realpath(path, real)) {
        rel_for_log(ctx, real, out, out_sz);
        if(out[0] && out[0] != '/') return;
    }
    // 3) Fallback to basename-only relative display.
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(out, out_sz, "%s", base && *base ? base : ".");
}

static bool is_delim_char(char c) {
    return isspace((unsigned char)c) || c=='"' || c=='\'' || c=='`' || c=='<' || c=='>' || c==',' || c==';' || c=='(' || c==')' || c=='[' || c==']' || c=='{' || c=='}' || c=='|' || c=='\r' || c=='\n';
}

static bool contains_scheme(const char *ptr, size_t len) {
    for(size_t i=0;i+2<len;i++) {
        if(ptr[i]==':' && ptr[i+1]=='/' && ptr[i+2]=='/') return true;
    }
    return false;
}

static bool is_candidate_token(const char *token, size_t len) {
    if(len < 3 || len > 512) return false;
    bool has_slash=false, has_dot=false, has_alpha=false;
    for(size_t i=0;i<len;i++) {
        unsigned char ch = (unsigned char)token[i];
        if(ch=='/' || ch=='\\') has_slash = true;
        if(ch=='.') has_dot = true;
        if(isalpha(ch)) has_alpha = true;
    }
    if(contains_scheme(token,len)) return true;
    if(has_slash) return true;
    if(has_dot && has_alpha) return true;
    return false;
}

typedef void (*token_cb)(const char *tok, size_t len, size_t start, size_t end, void *ud);

static void scan_tokens(const char *buf, size_t len, token_cb cb, void *ud) {
    size_t i=0;
    while(i<len) {
        while(i<len && is_delim_char(buf[i])) i++;
        size_t start=i;
        while(i<len && !is_delim_char(buf[i])) i++;
        size_t end=i;
        if(end>start) {
            size_t tok_len = end - start;
            if(is_candidate_token(buf+start, tok_len)) cb(buf+start, tok_len, start, end, ud);
        }
    }
}

typedef struct {
    StrList *list;
    size_t *refs;
} TokenAcc;

static void analysis_token_handler(const char *tok, size_t tlen, size_t start, size_t end, void *udata) {
    (void)start; (void)end;
    TokenAcc *u = (TokenAcc*)udata;
    if(!u || !u->list || !u->refs) return;
    if(u->list->count > 20000) return; // guardrail on memory
    char tmp[520];
    size_t copy = tlen < sizeof tmp - 1 ? tlen : sizeof tmp - 1;
    memcpy(tmp, tok, copy);
    tmp[copy] = '\0';
    strlist_append(u->list, tmp);
    (*(u->refs))++;
}

typedef struct {
    size_t start;
    size_t end;
    char value[PATH_MAX];
} Replacement;

static void sanitize_basename(const char *name, char *out, size_t out_sz) {
    if(!name || !out || out_sz==0) return;
    const char *dot = strrchr(name, '.');
    size_t base_len = dot ? (size_t)(dot - name) : strlen(name);
    size_t cur = base_len;
    // strip trailing segments of the form _<digits>, repeatedly
    while(cur > 0) {
        size_t scan = cur;
        while(scan > 0 && isdigit((unsigned char)name[scan-1])) scan--;
        if(scan == cur) break; // no trailing digits
        if(scan == 0 || name[scan-1] != '_') break;
        cur = scan - 1; // drop "_"
    }
    if(cur == 0) cur = base_len;
    size_t pos = 0;
    size_t limit = cur;
    if(limit >= out_sz) limit = out_sz - 1;
    memcpy(out, name, limit);
    pos = limit;
    if(dot && pos + strlen(dot) < out_sz) {
        strcpy(out + pos, dot);
    } else {
        out[pos] = '\0';
    }
}

static StrList g_analysis_tokens;

typedef struct {
    char path[PATH_MAX];
    char hash[65];
    char category[64];
    char sanitized[256];
} PatternEntry;

typedef struct {
    char sanitized[256];
    char category[64];
    PatternEntry *entries;
    size_t count;
    size_t cap;
} PatternGroup;

static PatternGroup *g_pattern_groups = NULL;
static size_t g_pattern_group_count = 0;

static void pattern_groups_reset(void) {
    for(size_t i=0;i<g_pattern_group_count;i++) {
        free(g_pattern_groups[i].entries);
    }
    free(g_pattern_groups);
    g_pattern_groups = NULL;
    g_pattern_group_count = 0;
}

static PatternGroup *pattern_group_get(const char *sanitized, const char *category, bool create) {
    for(size_t i=0;i<g_pattern_group_count;i++) {
        if(strcmp(g_pattern_groups[i].sanitized, sanitized)==0 && strcmp(g_pattern_groups[i].category, category)==0) return &g_pattern_groups[i];
    }
    if(!create) return NULL;
    PatternGroup *tmp = realloc(g_pattern_groups, (g_pattern_group_count + 1) * sizeof(PatternGroup));
    if(!tmp) return NULL;
    g_pattern_groups = tmp;
    PatternGroup *pg = &g_pattern_groups[g_pattern_group_count++];
    memset(pg, 0, sizeof *pg);
    snprintf(pg->sanitized, sizeof pg->sanitized, "%s", sanitized);
    snprintf(pg->category, sizeof pg->category, "%s", category);
    return pg;
}

static bool pattern_group_add(PatternGroup *pg, const PatternEntry *entry) {
    if(!pg || !entry) return false;
    if(pg->count == pg->cap) {
        size_t nc = pg->cap ? pg->cap * 2 : 8;
        PatternEntry *tmp = realloc(pg->entries, nc * sizeof(PatternEntry));
        if(!tmp) return false;
        pg->entries = tmp;
        pg->cap = nc;
    }
    pg->entries[pg->count++] = *entry;
    return true;
}

static bool dir_guard(const char *path, const struct stat *st, int depth, void *userdata) {
    (void)st; (void)userdata;
    if(depth > 100) return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if(strcmp(base, ".git")==0 || strcmp(base, ".gitarchive")==0 || strcmp(base, "identified")==0) return false;
    return true;
}

typedef struct {
    SweepContext *ctx;
    size_t files_seen;
    size_t dirs_seen;
    long long size_cap;
} ScanState;

static bool file_guard(const char *path, const struct stat *st, int depth, void *userdata) {
    (void)depth;
    ScanState *ss = (ScanState*)userdata;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if(base[0]=='.' && (strcmp(base,".git")==0 || strcmp(base,".gitarchive")==0)) return false;
    if(ss->size_cap > 0 && st->st_size > ss->size_cap) return false;
    ss->files_seen++;
    return true;
}

static int sweep_scan_hash(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_SCAN_HASH, lbl, sizeof lbl);
    log_sweep_start(lbl, "scan & hash starting");
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    (void)dir_count;
    (void)dir_count;
    (void)dir_count;
    (void)dir_count;
    size_t processed = 0;
    for(size_t i=0;i<file_count;i++) {
        char hash[65];
        if(svc_hash_file_ctx(ctx, files[i], hash, sizeof hash)==0) {
            processed++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
            SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
        }
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s files=%zu dirs=%zu hashed=%zu", lbl, file_count, dir_count, processed);
    return 0;
}

static void move_git_dir(const char *src, const char *dst_base, size_t idx) {
    char dest[PATH_MAX];
    if(strlen(dst_base) + 16 >= sizeof dest) return;
    snprintf(dest, sizeof dest, "%s/.git%zu", dst_base, idx);
    rename(src, dest);
}

static void collect_git_dirs(const char *root, const char *root_git, size_t *count) {
    DIR *d = opendir(root);
    if(!d) return;
    struct dirent *ent;
    while((ent = readdir(d))) {
        if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", root, ent->d_name);
        struct stat st;
        if(stat(path, &st)!=0) continue;
        if(S_ISDIR(st.st_mode)) {
            if(strcmp(ent->d_name, ".git")==0) {
                if(strcmp(path, root_git)!=0) {
                    (*count)++;
                }
            } else if(strcmp(ent->d_name, ".gitarchive")!=0) {
                collect_git_dirs(path, root_git, count);
            }
        }
    }
    closedir(d);
}

static int sweep_git_archive(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_GIT_ARCHIVE, lbl, sizeof lbl);
    log_sweep_start(lbl, "git archive relocation starting");
    char archive_dir[PATH_MAX];
    size_t rl = strlen(ctx->root);
    if(rl + 13 >= PATH_MAX) {
        SVC_LOG_WARN(ctx, "%s root path too long for git archive handling", lbl);
        return 0;
    }
    snprintf(archive_dir, sizeof archive_dir, "%s/.gitarchive", ctx->root);
    ensure_dir(archive_dir, 0755);
    char root_git[PATH_MAX];
    snprintf(root_git, sizeof root_git, "%s/.git", ctx->root);
    size_t count = 0;
    collect_git_dirs(ctx->root, root_git, &count);
    if(count == 0) {
        SVC_LOG_INFO(ctx, "%s no nested git directories", lbl);
        return 0;
    }
    size_t moved = 0;
    DIR *d = opendir(ctx->root);
    if(d) closedir(d); // placeholder to satisfy static analyzers
    // second pass relocates
    DIR *walk = opendir(ctx->root);
    if(!walk) return 0;
    struct dirent *ent;
    while((ent=readdir(walk))) {
        if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
        char path[PATH_MAX];
        if(!path_join(ctx->root, ent->d_name, path, sizeof path)) continue;
        struct stat st;
        if(stat(path,&st)!=0 || !S_ISDIR(st.st_mode)) continue;
        if(strcmp(ent->d_name,".git")==0) continue;
        if(strcmp(ent->d_name,".gitarchive")==0) continue;
        DIR *sub = opendir(path);
        if(!sub) continue;
        struct dirent *ent2;
        while((ent2=readdir(sub))) {
            if(strcmp(ent2->d_name,".")==0 || strcmp(ent2->d_name,"..")==0) continue;
            char gpath[PATH_MAX];
            if(!path_join(path, ent2->d_name, gpath, sizeof gpath)) continue;
            struct stat gst;
            if(stat(gpath,&gst)!=0 || !S_ISDIR(gst.st_mode)) continue;
            if(strcmp(ent2->d_name,".git")==0) {
                move_git_dir(gpath, archive_dir, ++moved);
                char rel[PATH_MAX]; sanitize_live_path(ctx, gpath, rel, sizeof rel);
                SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
            }
        }
        closedir(sub);
    }
    closedir(walk);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s relocated=%zu", lbl, moved);
    return 0;
}

typedef struct {
    const char *ext;
    const char *category;
} RouteRule;

static RouteRule g_route_rules[] = {
    {"c","c"}, {"h","c"},
    {"js","javascript"}, {"ts","javascript"},
    {"py","python"},
    {"rb","ruby"},
    {"php","php"}, {"module","php"}, {"install","php"},
    {"md","markdown"}, {"markdown","text"},
    {"css","css"}, {"scss","css"}, {"less","css"},
    {"json","json"},
    {"svg","image"}, {"png","image"}, {"jpg","image"}, {"jpeg","image"}, {"bmp","image"}, {"ico","image"}, {"gif","image"},
    {"xml","data"}, {"csv","data"}, {"sql","data"},
    {"twig","template"},
    {"yml","yml"}, {"yaml","yml"},
    {"map","map"},
    {"html","html"},
    {"txt","text"},
};

static const char *pick_category(const char *name) {
    if(strstr(name, ".tpl.php")) return "template";
    const char *dot = strrchr(name, '.');
    if(!dot || !dot[1]) return "unknown";
    const char *ext = dot + 1;
    for(size_t i=0;i<sizeof(g_route_rules)/sizeof(g_route_rules[0]);i++) {
        if(strcmp(ext, g_route_rules[i].ext)==0) return g_route_rules[i].category;
    }
    return "unknown";
}

static int sweep_category_create(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_CATEGORY_CREATE, lbl, sizeof lbl);
    const char *cats[] = {"unknown","archive","c","javascript","python","ruby","php","markdown","css","json","image","data","template","yml","map","html","text"};
    for(size_t i=0;i<sizeof(cats)/sizeof(cats[0]);i++) {
        char dir[PATH_MAX];
        path_join(ctx->root, cats[i], dir, sizeof dir);
        ensure_dir(dir, 0755);
    }
    SVC_LOG_INFO(ctx, "%s categories ensured", lbl);
    return 0;
}

static int sweep_file_move(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_FILE_MOVE, lbl, sizeof lbl);
    log_sweep_start(lbl, "file movement starting");
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    size_t moved = 0;
    for(size_t i=0;i<file_count;i++) {
        char base[NAME_MAX];
        path_basename(files[i], base, sizeof base);
        const char *cat = pick_category(base);
        char dest_dir[PATH_MAX];
        path_join(ctx->root, cat, dest_dir, sizeof dest_dir);
        ensure_dir(dest_dir, 0755);
        char dest[PATH_MAX];
        path_join(dest_dir, base, dest, sizeof dest);
        if(svc_rename_ctx(ctx, files[i], dest)==0) {
            moved++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
        }
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s moved=%zu", lbl, moved);
    return 0;
}

static bool hashes_equal(const char *a, const char *b) {
    if(!a || !b) return false;
    char ha[65], hb[65];
    if(svc_hash_file_ctx(NULL, a, ha, sizeof ha)!=0) return false;
    if(svc_hash_file_ctx(NULL, b, hb, sizeof hb)!=0) return false;
    return strcmp(ha, hb)==0;
}

static int sweep_sanitize_underscores(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_SANITIZE_UNDERSCORES, lbl, sizeof lbl);
    log_sweep_start(lbl, "sanitize underscores starting");
    if(!ctx->enable_sanitize_underscores) {
        SVC_LOG_INFO(ctx, "%s skipped (disabled)", lbl);
        return 0;
    }
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    size_t renamed = 0, dedup_removed = 0, conflicts = 0;
    for(size_t i=0;i<file_count;i++) {
        char base[NAME_MAX]; path_basename(files[i], base, sizeof base);
        char sanitized[NAME_MAX]; sanitize_basename(base, sanitized, sizeof sanitized);
        if(strcmp(base, sanitized)==0) { free(files[i]); continue; }
        char dir[PATH_MAX]; path_dirname(files[i], dir, sizeof dir);
        char dest[PATH_MAX];
        if(!path_join(dir, sanitized, dest, sizeof dest)) { free(files[i]); continue; }
        if(svc_rename_ctx(ctx, files[i], dest)==0) {
            renamed++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
            free(files[i]);
            continue;
        }
        if(errno==EEXIST || errno==ENOTEMPTY) {
            if(hashes_equal(files[i], dest)) {
                if(svc_unlink_ctx(ctx, files[i])==0) {
                    dedup_removed++;
                    char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
                    SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
                }
            } else {
                conflicts++;
                SVC_LOG_WARN(ctx, "%s conflict: %s -> %s exists with different content", lbl, files[i], dest);
            }
        } else {
            conflicts++;
            SVC_LOG_WARN(ctx, "%s rename failed %s -> %s (%s)", lbl, files[i], dest, strerror(errno));
        }
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s renamed=%zu dedup_removed=%zu conflicts=%zu", lbl, renamed, dedup_removed, conflicts);
    return 0;
}

static int sweep_content_analysis(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_CONTENT_ANALYSIS, lbl, sizeof lbl);
    log_sweep_start(lbl, "content analysis starting");
    if(!ctx->enable_content_analysis) {
        strlist_free(&g_analysis_tokens);
        strlist_init(&g_analysis_tokens);
        SVC_LOG_INFO(ctx, "%s skipped (disabled)", lbl);
        return 0;
    }
    strlist_free(&g_analysis_tokens);
    strlist_init(&g_analysis_tokens);
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    size_t refs = 0;
    for(size_t i=0;i<file_count;i++) {
        if(forensic_should_stop()) break;
        struct stat st;
        if(stat(files[i], &st)!=0 || !S_ISREG(st.st_mode)) { free(files[i]); continue; }
        if(ctx->size_cap_bytes > 0 && st.st_size > ctx->size_cap_bytes) { free(files[i]); continue; }
        char *buf=NULL; size_t len=0;
        int rc = read_file_limited(files[i], 512 * 1024, &buf, &len);
        if(rc!=0 || !buf) { free(files[i]); continue; }
        TokenAcc ud = { .list = &g_analysis_tokens, .refs = &refs };
        scan_tokens(buf, len, analysis_token_handler, &ud);
        free(buf);
        char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
        SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    strlist_dedupe(&g_analysis_tokens);
    SVC_LOG_INFO(ctx, "%s refs=%zu unique_tokens=%zu", lbl, refs, g_analysis_tokens.count);
    return 0;
}

static int sweep_path_hash_dedup(SweepContext *ctx) {
    (void)ctx;
    char lbl[16]; sweep_label(SWEEP_PATH_HASH_DEDUP, lbl, sizeof lbl);
    log_sweep_start(lbl, "path hash dedup starting");
    if(g_analysis_tokens.count == 0) {
        SVC_LOG_INFO(ctx, "%s skipped (no tokens)", lbl);
        return 0;
    }
    StrList hashes; strlist_init(&hashes);
    for(size_t i=0;i<g_analysis_tokens.count;i++) {
        const char *tok = g_analysis_tokens.items[i];
        char hex[65];
        if(svc_hash_bytes_ctx(ctx, (const unsigned char*)tok, strlen(tok), hex, sizeof hex)==0) {
            strlist_append(&hashes, hex);
        }
    }
    strlist_dedupe(&hashes);
    SVC_LOG_INFO(ctx, "%s tokens=%zu unique_hashes=%zu", lbl, g_analysis_tokens.count, hashes.count);
    strlist_free(&hashes);
    return 0;
}

static bool resolve_token_to_rel(const SweepContext *ctx, const char *file_dir, const char *token, char *out, size_t out_sz) {
    if(!ctx || !token || !out || out_sz==0) return false;
    char combined[PATH_MAX];
    if(token[0]=='/' || token[0]=='\\') {
        snprintf(combined, sizeof combined, "%s", token);
    } else {
        if(!path_join(file_dir, token, combined, sizeof combined)) return false;
    }
    char real[PATH_MAX];
    if(!realpath(combined, real)) return false;
    size_t rl = strlen(ctx->root);
    if(strncmp(real, ctx->root, rl)!=0 || (real[rl] && real[rl]!='/')) return false;
    const char *rel = real + rl;
    if(*rel=='/') rel++;
    snprintf(out, out_sz, "./%s", rel);
    return true;
}

typedef struct {
    const SweepContext *ctx;
    const char *file_dir;
    Replacement *repls;
    size_t *repl_count;
    size_t *repl_cap;
} RefactorCtx;

static void add_replacement(RefactorCtx *rc, size_t start, size_t end, const char *val) {
    if(!rc || !val || !rc->repl_count || !rc->repl_cap) return;
    if(*rc->repl_count == *rc->repl_cap) {
        size_t nc = *rc->repl_cap ? (*rc->repl_cap) * 2 : 8;
        Replacement *tmp = realloc(rc->repls, nc * sizeof(Replacement));
        if(!tmp) return;
        rc->repls = tmp;
        *rc->repl_cap = nc;
    }
    Replacement *r = &rc->repls[(*rc->repl_count)++];
    r->start = start;
    r->end = end;
    snprintf(r->value, sizeof r->value, "%s", val);
}

static void refactor_token_handler(const char *tok, size_t tlen, size_t start, size_t end, void *udata) {
    RefactorCtx *rc = (RefactorCtx*)udata;
    if(!rc || !rc->ctx || !rc->file_dir) return;
    char tmp[520];
    size_t copy = tlen < sizeof tmp - 1 ? tlen : sizeof tmp - 1;
    memcpy(tmp, tok, copy);
    tmp[copy] = '\0';
    char replacement[PATH_MAX];
    if(!resolve_token_to_rel(rc->ctx, rc->file_dir, tmp, replacement, sizeof replacement)) return;
    if(strcmp(tmp, replacement)==0) return;
    add_replacement(rc, start, end, replacement);
}

static bool apply_repls(char **buf, size_t *len, Replacement *repls, size_t repl_count) {
    if(!buf || !*buf || !len || repl_count==0) return false;
    // sort by start
    for(size_t i=0;i<repl_count;i++) {
        for(size_t j=i+1;j<repl_count;j++) {
            if(repls[j].start < repls[i].start) {
                Replacement tmp = repls[i];
                repls[i] = repls[j];
                repls[j] = tmp;
            }
        }
    }
    size_t cap = *len + repl_count * 64;
    char *out = malloc(cap + 1);
    if(!out) return false;
    size_t src = 0, dst = 0;
    for(size_t i=0;i<repl_count;i++) {
        if(repls[i].start > *len) continue;
        if(repls[i].end > *len) repls[i].end = *len;
        size_t chunk = repls[i].start - src;
        if(dst + chunk + 1 >= cap) { cap = (cap + chunk + 1) * 2; out = realloc(out, cap + 1); if(!out) return false; }
        memcpy(out + dst, *buf + src, chunk);
        dst += chunk;
        size_t vlen = strlen(repls[i].value);
        if(dst + vlen + 1 >= cap) { cap = (cap + vlen + 1) * 2; out = realloc(out, cap + 1); if(!out) return false; }
        memcpy(out + dst, repls[i].value, vlen);
        dst += vlen;
        src = repls[i].end;
    }
    if(src < *len) {
        size_t chunk = *len - src;
        if(dst + chunk + 1 >= cap) { cap = (cap + chunk + 1) * 2; out = realloc(out, cap + 1); if(!out) return false; }
        memcpy(out + dst, *buf + src, chunk);
        dst += chunk;
    }
    out[dst] = '\0';
    free(*buf);
    *buf = out;
    *len = dst;
    return true;
}

static int sweep_path_refactor(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_PATH_REFACTOR, lbl, sizeof lbl);
    if(!ctx->enable_path_refactor) {
        SVC_LOG_INFO(ctx, "%s path refactor skipped (disabled)", lbl);
        return 0;
    }
    log_sweep_start(lbl, "path refactor starting");
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    size_t files_changed = 0, replacements = 0;
    for(size_t i=0;i<file_count;i++) {
        if(forensic_should_stop()) break;
        char dir[PATH_MAX];
        path_dirname(files[i], dir, sizeof dir);
        char *buf=NULL; size_t len=0;
        int rc = read_file_limited(files[i], 512 * 1024, &buf, &len);
        if(rc!=0 || !buf) { free(files[i]); continue; }
        Replacement *repls = NULL; size_t repl_count=0, repl_cap=0;
        RefactorCtx rctx = {.ctx=ctx, .file_dir=dir, .repls=repls, .repl_count=&repl_count, .repl_cap=&repl_cap};
        scan_tokens(buf, len, refactor_token_handler, &rctx);
        if(repl_count>0) {
            if(apply_repls(&buf, &len, rctx.repls, repl_count)) {
                FILE *f = fopen(files[i], "wb");
                if(f) {
                    fwrite(buf,1,len,f);
                    fclose(f);
                    files_changed++;
                    replacements += repl_count;
                    char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
                    SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
                }
            }
        }
        free(rctx.repls);
        free(buf);
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s files_changed=%zu replacements=%zu", lbl, files_changed, replacements);
    return 0;
}

static void remove_empty_dirs(const char *root, int depth) {
    if(depth > 100) return;
    DIR *d = opendir(root);
    if(!d) return;
    struct dirent *ent;
    while((ent=readdir(d))) {
        if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
        char path[PATH_MAX];
        snprintf(path,sizeof path,"%s/%s", root, ent->d_name);
        struct stat st;
        if(stat(path,&st)!=0) continue;
        if(S_ISDIR(st.st_mode)) {
            remove_empty_dirs(path, depth+1);
            DIR *inner = opendir(path);
            if(inner) {
                struct dirent *tmp;
                int has_items = 0;
                while((tmp=readdir(inner))) {
                    if(strcmp(tmp->d_name,".") && strcmp(tmp->d_name,"..")) { has_items=1; break; }
                }
                closedir(inner);
                if(!has_items) rmdir(path);
            }
        }
    }
    closedir(d);
}

static int sweep_empty_dir_cleanup(SweepContext *ctx) {
    // NOTE: keep this sweep last and operate on the final root, not any staging temp dir.
    char lbl[16]; sweep_label(SWEEP_EMPTY_DIR_CLEAN, lbl, sizeof lbl);
    log_sweep_start(lbl, "empty dir cleanup starting");
    remove_empty_dirs(ctx->root, 0);
    SVC_LOG_INFO(ctx, "%s cleanup done", lbl);
    return 0;
}

static int sweep_filename_pattern(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_FILENAME_PATTERN, lbl, sizeof lbl);
    log_sweep_start(lbl, "filename pattern dedup starting");
    pattern_groups_reset();
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    size_t duplicates = 0;
    for(size_t i=0;i<file_count;i++) {
        char base[NAME_MAX]; path_basename(files[i], base, sizeof base);
        char sanitized[256]; sanitize_basename(base, sanitized, sizeof sanitized);
        if(!sanitized[0]) snprintf(sanitized,sizeof sanitized,"%s", base);
        const char *cat = pick_category(base);
        char hash[65];
        if(svc_hash_file_ctx(ctx, files[i], hash, sizeof hash)!=0) { free(files[i]); continue; }
        PatternGroup *pg = pattern_group_get(sanitized, cat, true);
        if(!pg) { free(files[i]); continue; }
        bool dup=false;
        for(size_t j=0;j<pg->count;j++) {
            if(strcmp(pg->entries[j].hash, hash)==0) { dup=true; break; }
        }
        if(dup) {
            if(svc_unlink_ctx(ctx, files[i])==0) {
                duplicates++;
                char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
                SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
            }
            free(files[i]);
            continue;
        }
        PatternEntry pe;
        memset(&pe,0,sizeof pe);
        snprintf(pe.path, sizeof pe.path, "%s", files[i]);
        snprintf(pe.hash, sizeof pe.hash, "%s", hash);
        snprintf(pe.category, sizeof pe.category, "%s", cat);
        snprintf(pe.sanitized, sizeof pe.sanitized, "%s", sanitized);
        pattern_group_add(pg, &pe);
        free(files[i]);
    }
    free(files);
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s duplicates_removed=%zu groups=%zu", lbl, duplicates, g_pattern_group_count);
    return 0;
}

static int sweep_pattern_groups(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_PATTERN_GROUPS, lbl, sizeof lbl);
    log_sweep_start(lbl, "pattern grouping starting");
    size_t moved_total = 0;
    for(size_t i=0;i<g_pattern_group_count;i++) {
        PatternGroup *pg = &g_pattern_groups[i];
        if(pg->count < 2) continue;
        char group_dir[PATH_MAX];
        if(!path_join(ctx->root, pg->category, group_dir, sizeof group_dir)) continue;
        size_t len = strlen(group_dir);
        if(len + 4 + strlen(pg->sanitized) >= sizeof group_dir) continue;
        snprintf(group_dir + len, sizeof group_dir - len, "/%s.d", pg->sanitized);
        ensure_dir(group_dir, 0755);
        char manifest_path[PATH_MAX];
        FILE *manifest = NULL;
        if(path_join(group_dir, "manifest.json", manifest_path, sizeof manifest_path)) {
            manifest = fopen(manifest_path, "w");
            if(manifest) fputs("[\n", manifest);
        }
        // derive base/ext from sanitized stub for consistent indexing
        char stub_base[NAME_MAX], stub_ext[NAME_MAX];
        {
            const char *dot = strrchr(pg->sanitized, '.');
            if(dot) {
                size_t b = (size_t)(dot - pg->sanitized);
                if(b >= sizeof stub_base) b = sizeof stub_base - 1;
                memcpy(stub_base, pg->sanitized, b);
                stub_base[b] = '\0';
                snprintf(stub_ext, sizeof stub_ext, "%s", dot);
            } else {
                snprintf(stub_base, sizeof stub_base, "%s", pg->sanitized);
                stub_ext[0] = '\0';
            }
        }
        for(size_t j=0;j<pg->count;j++) {
            char trimmed[NAME_MAX];
            size_t bl = strlen(stub_base);
            size_t max_bl = sizeof trimmed - 32;
            if(bl > max_bl) bl = max_bl;
            memcpy(trimmed, stub_base, bl);
            trimmed[bl] = '\0';
            char dest_name[NAME_MAX];
            char idxbuf[32]; snprintf(idxbuf, sizeof idxbuf, "%zu", j);
            snprintf(dest_name, sizeof dest_name, "%.*s_%s%s", (int)bl, trimmed, idxbuf, stub_ext);
            char dest[PATH_MAX];
            if(!path_join(group_dir, dest_name, dest, sizeof dest)) continue;
        if(svc_rename_ctx(ctx, pg->entries[j].path, dest)==0) {
            moved_total++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            SVC_LOG_LIVE_STATUS(ctx, lbl, rel);
            snprintf(pg->entries[j].path, sizeof pg->entries[j].path, "%s", dest);
        }
            if(manifest) {
                fprintf(manifest, "  {\"path\": \"%s\", \"hash\": \"%s\"}%s\n",
                        pg->entries[j].path, pg->entries[j].hash, (j+1<pg->count)?",":"");
            }
        }
        if(manifest) {
            fputs("]\n", manifest);
            fclose(manifest);
        }
    }
    SVC_LOG_LIVE_DONE(ctx);
    SVC_LOG_INFO(ctx, "%s grouped_moves=%zu", lbl, moved_total);
    pattern_groups_reset();
    return 0;
}

size_t register_sweeps(Sweep *out, size_t max) {
    Sweep all[] = {
        {SWEEP_IDENTIFIERS, "identifiers", sweep_identifiers},
        {SWEEP_SCAN_HASH, "scan & hash", sweep_scan_hash},
        {SWEEP_GIT_ARCHIVE, "git archive relocation", sweep_git_archive},
        {SWEEP_CATEGORY_CREATE, "category creation", sweep_category_create},
        {SWEEP_FILE_MOVE, "file movement", sweep_file_move},
        {SWEEP_SANITIZE_UNDERSCORES, "sanitize underscores", sweep_sanitize_underscores},
        {SWEEP_CONTENT_ANALYSIS, "content analysis", sweep_content_analysis},
        {SWEEP_PATH_HASH_DEDUP, "path hash dedup", sweep_path_hash_dedup},
        {SWEEP_PATH_REFACTOR, "path refactor", sweep_path_refactor},
        {SWEEP_FILENAME_PATTERN, "filename pattern dedup", sweep_filename_pattern},
        {SWEEP_PATTERN_GROUPS, "pattern grouping", sweep_pattern_groups},
        {SWEEP_EMPTY_DIR_CLEAN, "empty dir cleanup", sweep_empty_dir_cleanup},
        {SWEEP_REPORTING, "reporting", NULL},
    };
    size_t count = sizeof(all)/sizeof(all[0]);
    if(out && max>0) {
        size_t n = count < max ? count : max;
        memcpy(out, all, n * sizeof(Sweep));
        return n;
    }
    return count;
}

int run_all_sweeps(SweepContext *ctx) {
    Sweep sweeps[16];
    size_t count = register_sweeps(sweeps, 16);
    double durations[16]={0};
    bool ran[16]={0};
    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);
    int rc = 0;
    for(size_t i=0;i<count;i++) {
        if(!sweeps[i].run) continue;
        if(forensic_should_stop()) break;
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        rc = sweeps[i].run(ctx);
        clock_gettime(CLOCK_MONOTONIC, &end);
        durations[i] = elapsed_seconds(&start, &end);
        ran[i] = true;
        if(rc!=0) break;
    }
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    double total_seconds = elapsed_seconds(&total_start, &total_end);
    log_timing_summary(ctx, sweeps, durations, ran, count, total_seconds);
    if(rc!=0) return rc;
    return 0;
}

int run_prewarm(SweepContext *ctx) { (void)ctx; return 0; }
