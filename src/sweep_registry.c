#define _GNU_SOURCE
#include "sweep_registry.h"
#include "logging.h"
#include "sha256.h"
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

static void log_timing_summary(const Sweep *sweeps, const double *durations, const bool *ran, size_t count, double total_seconds) {
    if(!sweeps || !durations || !ran) return;
    log_info("%sSweep timing summary%s", CLR_MAGENTA, CLR_RESET);
    for(size_t i=0;i<count;i++) {
        if(!ran[i]) continue;
        char lbl[32]; sweep_label(sweeps[i].id, lbl, sizeof lbl);
        char dur[32]; format_duration(durations[i], true, dur, sizeof dur);
        log_info("  %s%-18s%s %-24s %s%s%s", CLR_CYAN, lbl, CLR_RESET, sweeps[i].name, CLR_GREEN, dur, CLR_RESET);
    }
    char total[32]; format_duration(total_seconds, false, total, sizeof total);
    log_info("%sTotal elapsed%s %s%s%s", CLR_MAGENTA, CLR_RESET, CLR_GREEN, total, CLR_RESET);
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
    bool drupal=false, symfony=false, composer=false, node=false;
    bool drupal_app = false;
    {
        bool looks_like_root = has_drupal_root(dir);
        bool mentions_core = composer_buf && strstr(composer_buf, "drupal/core");
        bool is_component = composer_buf &&
            (strstr(composer_buf, "drupal-module") || strstr(composer_buf, "drupal-theme") || strstr(composer_buf, "drupal-profile"));
        if((looks_like_root || mentions_core) && !is_component) drupal_app = true;
    }
    if(drupal_app && (mask & IDENT_DRUPAL)) {
        drupal = true;
    }
    bool symfony_pkg = composer_buf &&
        (strstr(composer_buf, "\"symfony/framework-bundle\"") ||
         strstr(composer_buf, "\"symfony/symfony\"") ||
         strstr(composer_buf, "\"symfony/http-kernel\"") ||
         strstr(composer_buf, "\"symfony/console\"") ||
         strstr(composer_buf, "\"symfony/routing\""));
    bool symfony_console = has_child(dir, "bin/console");
    bool symfony_config = has_child(dir, "config") || has_child(dir, "app/config");
    if(!drupal_app && (mask & IDENT_SYMFONY) && has_composer) {
        int signals = (symfony_pkg?1:0) + (symfony_console?1:0) + (symfony_config?1:0);
        if(signals >= 2) symfony = true;
    }
    if(!drupal && !symfony && (mask & IDENT_COMPOSER) && has_composer) composer = true;
    if((mask & IDENT_NODE) && has_pkg) node = true;

    if(composer_buf) free(composer_buf);
    if(package_buf) free(package_buf);

    if(drupal) {
        snprintf(key, key_sz, "drupal");
        char rel[PATH_MAX];
        rel_for_log(ctx, dir, rel, sizeof rel);
        const char *label = composer_name[0] ? composer_name : (rel[0] ? rel : dir);
        safe_name(label, name, name_sz);
        return true;
    }
    if(symfony) {
        snprintf(key, key_sz, "symfony");
        safe_name(composer_name[0]?composer_name:dir, name, name_sz);
        return true;
    }
    if(composer) {
        snprintf(key, key_sz, "composer");
        safe_name(composer_name[0]?composer_name:dir, name, name_sz);
        return true;
    }
    if(node) {
        snprintf(key, key_sz, "node");
        safe_name(package_name[0]?package_name:dir, name, name_sz);
        return true;
    }
    return false;
}

static bool move_identified(const SweepContext *ctx, const char *dir, const char *key, const char *name) {
    if(!ctx || !dir || !key || !name) return false;
    if(strcmp(dir, ctx->root)==0) {
        log_warn("identifiers: refusing to move root directory");
        return false;
    }
    char target[PATH_MAX];
    if(!path_join(ctx->root, "identified", target, sizeof target)) return false;
    ensure_dir(target, 0755);
    size_t len = strlen(target);
    if(len + strlen(key) + strlen(name) + 3 >= sizeof target) return false;
    snprintf(target + len, sizeof target - len, "/%s", key);
    ensure_dir(target, 0755);
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
        if(rename(dir, dest)==0) {
            moved = true;
            break;
        }
        if(errno!=EEXIST && errno!=ENOTEMPTY) break;
    }
    if(!moved) {
        log_warn("identifiers: rename failed %s -> %s (%s)", dir, target, strerror(errno));
        return false;
    }
    char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
    char lbl[16]; sweep_label(SWEEP_IDENTIFIERS, lbl, sizeof lbl);
    log_live_status(lbl, rel);
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
        log_info("%s skipped (disabled)", lbl);
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
    log_live_done();
    log_info("%s identified=%zu", lbl, identified);
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

static bool sha256_bytes(const unsigned char *data, size_t len, char *out_hex, size_t out_hex_sz) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)==1 &&
              EVP_DigestUpdate(ctx, data, len)==1 &&
              EVP_DigestFinal_ex(ctx, digest, &dlen)==1;
    EVP_MD_CTX_free(ctx);
    if(!ok) return false;
    static const char *hex = "0123456789abcdef";
    if(out_hex_sz < dlen*2 + 1) return false;
    for(unsigned int i=0;i<dlen;i++) {
        out_hex[i*2] = hex[(digest[i] >> 4) & 0xF];
        out_hex[i*2+1] = hex[digest[i] & 0xF];
    }
    out_hex[dlen*2] = '\0';
    return true;
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

typedef struct {
    char category[64];
    size_t count;
} CategoryCounter;

typedef struct {
    const char *from;
    const char *to;
} ExtensionRewrite;

typedef struct {
    const char *extension;
    const char *category;
} ExtensionCategory;

static const ExtensionRewrite EXTENSION_REWRITES[] = {
    {"jpeg", "jpg"},
};

static const ExtensionCategory EXTENSION_CATEGORIES[] = {
    {"c", "c"},
    {"h", "c"},
    {"js", "javascript"},
    {"py", "python"},
    {"rb", "ruby"},
    {"php", "php"},
    {"module", "php"},
    {"install", "php"},
    {"css", "css"},
    {"scss", "css"},
    {"less", "css"},
    {"json", "json"},
    {"xml", "data"},
    {"csv", "data"},
    {"sql", "data"},
    {"twig", "template"},
    {"yml", "yml"},
    {"yaml", "yml"},
    {"map", "map"},
    {"html", "html"},
    {"txt", "text"},
    {"pdf", "document"},
    {"doc", "document"},
    {"docx", "document"},
    {"dot", "document"},
    {"dotx", "document"},
    {"rtf", "document"},
    {"odt", "document"},
    {"ott", "document"},
    {"pages", "document"},
    {"wpd", "document"},
    {"wps", "document"},
    {"abw", "document"},
    {"djvu", "document"},
    {"xps", "document"},
    {"oxps", "document"},
    {"tex", "document"},
    {"latex", "document"},
    {"bib", "document"},
    {"one", "document"},
    {"pub", "document"},
    {"fodt", "document"},
    {"docm", "document"},
    {"dotm", "document"},
    {"md", "markdown"},
    {"markdown", "markdown"},
    {"mdown", "markdown"},
    {"epub", "ebook"},
    {"mobi", "ebook"},
    {"azw", "ebook"},
    {"azw3", "ebook"},
    {"fb2", "ebook"},
    {"lit", "ebook"},
    {"xls", "spreadsheet"},
    {"xlsx", "spreadsheet"},
    {"xlsm", "spreadsheet"},
    {"xlsb", "spreadsheet"},
    {"xlt", "spreadsheet"},
    {"xltx", "spreadsheet"},
    {"xltm", "spreadsheet"},
    {"ods", "spreadsheet"},
    {"ots", "spreadsheet"},
    {"numbers", "spreadsheet"},
    {"ppt", "presentation"},
    {"pptx", "presentation"},
    {"pptm", "presentation"},
    {"pps", "presentation"},
    {"ppsx", "presentation"},
    {"pot", "presentation"},
    {"potx", "presentation"},
    {"odp", "presentation"},
    {"key", "presentation"},
    {"show", "presentation"},
    {"log", "text"},
    {"ini", "text"},
    {"conf", "text"},
    {"cfg", "text"},
    {"cnf", "text"},
    {"properties", "text"},
    {"props", "text"},
    {"toml", "text"},
    {"lock", "text"},
    {"nfo", "text"},
    {"asc", "text"},
    {"pem", "text"},
    {"crt", "text"},
    {"cer", "text"},
    {"keyfile", "text"},
    {"env", "text"},
    {"editorconfig", "text"},
    {"gitignore", "text"},
    {"gitattributes", "text"},
    {"dockerignore", "text"},
    {"rst", "text"},
    {"org", "text"},
    {"adoc", "text"},
    {"asciidoc", "text"},
    {"srt", "text"},
    {"vtt", "text"},
    {"sub", "text"},
    {"ass", "text"},
    {"ssa", "text"},
    {"readme", "text"},
    {"mp3", "audio"},
    {"wav", "audio"},
    {"flac", "audio"},
    {"aac", "audio"},
    {"m4a", "audio"},
    {"ogg", "audio"},
    {"oga", "audio"},
    {"opus", "audio"},
    {"wma", "audio"},
    {"aiff", "audio"},
    {"aif", "audio"},
    {"mid", "audio"},
    {"midi", "audio"},
    {"amr", "audio"},
    {"caf", "audio"},
    {"alac", "audio"},
    {"ape", "audio"},
    {"mka", "audio"},
    {"ra", "audio"},
    {"weba", "audio"},
    {"mp4", "video"},
    {"mov", "video"},
    {"avi", "video"},
    {"mkv", "video"},
    {"webm", "video"},
    {"m4v", "video"},
    {"wmv", "video"},
    {"flv", "video"},
    {"mpg", "video"},
    {"mpeg", "video"},
    {"mpe", "video"},
    {"3gp", "video"},
    {"3g2", "video"},
    {"ogv", "video"},
    {"mts", "video"},
    {"m2ts", "video"},
    {"ts", "video"},
    {"vob", "video"},
    {"rm", "video"},
    {"rmvb", "video"},
    {"svg", "image"},
    {"svgz", "image"},
    {"png", "image"},
    {"jpg", "image"},
    {"gif", "image"},
    {"webp", "image"},
    {"avif", "image"},
    {"heic", "image"},
    {"heif", "image"},
    {"tiff", "image"},
    {"tif", "image"},
    {"bmp", "image"},
    {"dib", "image"},
    {"ico", "image"},
    {"cur", "image"},
    {"jfif", "image"},
    {"pjpeg", "image"},
    {"pjp", "image"},
    {"apng", "image"},
    {"raw", "image"},
    {"cr2", "image"},
    {"cr3", "image"},
    {"nef", "image"},
    {"arw", "image"},
    {"dng", "image"},
    {"orf", "image"},
    {"rw2", "image"},
    {"raf", "image"},
    {"psd", "design"},
    {"psb", "design"},
    {"ai", "design"},
    {"eps", "design"},
    {"indd", "design"},
    {"indt", "design"},
    {"idml", "design"},
    {"xcf", "design"},
    {"kra", "design"},
    {"sketch", "design"},
    {"fig", "design"},
    {"afdesign", "design"},
    {"afphoto", "design"},
    {"afpub", "design"},
    {"clip", "design"},
    {"csp", "design"},
    {"ase", "design"},
    {"aco", "design"},
    {"blend", "model"},
    {"fbx", "model"},
    {"obj", "model"},
    {"stl", "model"},
    {"glb", "model"},
    {"gltf", "model"},
    {"dae", "model"},
    {"3ds", "model"},
    {"ply", "model"},
    {"usdz", "model"},
    {"usd", "model"},
    {"abc", "model"},
    {"step", "cad"},
    {"stp", "cad"},
    {"iges", "cad"},
    {"igs", "cad"},
    {"dwg", "cad"},
    {"dxf", "cad"},
    {"go", "code"},
    {"rs", "code"},
    {"swift", "code"},
    {"kt", "code"},
    {"kts", "code"},
    {"java", "code"},
    {"cs", "code"},
    {"lua", "code"},
    {"sh", "code"},
    {"bash", "code"},
    {"zsh", "code"},
    {"fish", "code"},
    {"ps1", "code"},
    {"bat", "code"},
    {"cmd", "code"},
    {"dart", "code"},
    {"scala", "code"},
    {"vue", "code"},
    {"svelte", "code"},
};

static void normalize_extension(const char *raw, char *out, size_t out_sz);
static void normalize_final_extension(const char *name, char *out, size_t out_sz);

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
        if(sha256_file(files[i], hash, sizeof hash)==0) {
            processed++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
            log_live_status(lbl, rel);
        }
        free(files[i]);
    }
    free(files);
    log_live_done();
    log_info("%s files=%zu dirs=%zu hashed=%zu", lbl, file_count, dir_count, processed);
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
        log_warn("%s root path too long for git archive handling", lbl);
        return 0;
    }
    snprintf(archive_dir, sizeof archive_dir, "%s/.gitarchive", ctx->root);
    ensure_dir(archive_dir, 0755);
    char root_git[PATH_MAX];
    snprintf(root_git, sizeof root_git, "%s/.git", ctx->root);
    size_t count = 0;
    collect_git_dirs(ctx->root, root_git, &count);
    if(count == 0) {
        log_info("%s no nested git directories", lbl);
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
                log_live_status(lbl, rel);
            }
        }
        closedir(sub);
    }
    closedir(walk);
    log_live_done();
    log_info("%s relocated=%zu", lbl, moved);
    return 0;
}

static const char *pick_category(const char *name) {
    if(strstr(name, ".tpl.php")) return "template";
    const char *dot = strrchr(name, '.');
    if(!dot || !dot[1]) return "unknown";
    char ext[NAME_MAX];
    normalize_extension(dot + 1, ext, sizeof ext);
    for(size_t i=0;i<sizeof(EXTENSION_CATEGORIES)/sizeof(EXTENSION_CATEGORIES[0]);i++) {
        if(strcmp(ext, EXTENSION_CATEGORIES[i].extension)==0) {
            return EXTENSION_CATEGORIES[i].category;
        }
    }
    return "unknown";
}

static void normalize_extension(const char *raw, char *out, size_t out_sz) {
    if(out_sz == 0) return;
    snprintf(out, out_sz, "%s", raw);
    for(char *p = out; *p; p++) {
        *p = (char)tolower((unsigned char)*p);
    }
    for(size_t i=0;i<sizeof(EXTENSION_REWRITES)/sizeof(EXTENSION_REWRITES[0]);i++) {
        if(strcmp(out, EXTENSION_REWRITES[i].from)==0) {
            snprintf(out, out_sz, "%s", EXTENSION_REWRITES[i].to);
            return;
        }
    }
}

static void normalize_final_extension(const char *name, char *out, size_t out_sz) {
    if(out_sz == 0) return;
    char original[NAME_MAX];
    snprintf(original, sizeof original, "%s", name);
    const char *dot = strrchr(original, '.');
    if(!dot || !dot[1]) {
        snprintf(out, out_sz, "%s", original);
        return;
    }
    char ext[NAME_MAX];
    normalize_extension(dot + 1, ext, sizeof ext);
    size_t base_len = (size_t)(dot - original);
    size_t ext_len = strlen(ext);
    if(base_len + 1 + ext_len >= out_sz) {
        size_t available = out_sz > 1 + ext_len ? out_sz - 1 - ext_len - 1 : 0;
        if(base_len > available) base_len = available;
        if(base_len + 1 + ext_len >= out_sz && ext_len > 0) {
            ext_len = out_sz > base_len + 2 ? out_sz - base_len - 2 : 0;
        }
    }
    size_t pos = 0;
    if(base_len > 0) {
        memcpy(out, original, base_len);
        pos = base_len;
    }
    if(pos + 1 < out_sz) out[pos++] = '.';
    if(ext_len > 0 && pos < out_sz) {
        size_t copy = ext_len;
        if(pos + copy >= out_sz) copy = out_sz - pos - 1;
        memcpy(out + pos, ext, copy);
        pos += copy;
    }
    out[pos < out_sz ? pos : out_sz - 1] = '\0';
}

static int cmp_string_ptrs(const void *a, const void *b) {
    const char *const *sa = (const char *const *)a;
    const char *const *sb = (const char *const *)b;
    return strcmp(*sa, *sb);
}

static size_t next_category_index(CategoryCounter **counters, size_t *count, size_t *cap, const char *category) {
    for(size_t i=0;i<*count;i++) {
        if(strcmp((*counters)[i].category, category)==0) {
            return ++(*counters)[i].count;
        }
    }
    if(*count == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        CategoryCounter *tmp = realloc(*counters, nc * sizeof(CategoryCounter));
        if(!tmp) return 0;
        *counters = tmp;
        *cap = nc;
    }
    CategoryCounter *cc = &(*counters)[(*count)++];
    memset(cc, 0, sizeof *cc);
    snprintf(cc->category, sizeof cc->category, "%s", category);
    cc->count = 1;
    return cc->count;
}

static void build_renamed_basename(const char *category, const char *name, size_t index, char *out, size_t out_sz) {
    const char *dot = strrchr(name, '.');
    if(dot && dot[1]) {
        char ext[NAME_MAX];
        normalize_extension(dot + 1, ext, sizeof ext);
        int max_ext = (int)(out_sz > strlen(category) + 10 ? out_sz - strlen(category) - 10 : 0);
        snprintf(out, out_sz, "%s_%07zu.%.*s", category, index, max_ext, ext);
    } else {
        snprintf(out, out_sz, "%s_%07zu", category, index);
    }
}

static int sweep_category_create(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_CATEGORY_CREATE, lbl, sizeof lbl);
    const char *cats[] = {"unknown","archive","c","javascript","python","ruby","php","markdown","css","json","image","video","audio","document","ebook","spreadsheet","presentation","design","model","cad","code","data","template","yml","map","html","text"};
    for(size_t i=0;i<sizeof(cats)/sizeof(cats[0]);i++) {
        char dir[PATH_MAX];
        path_join(ctx->root, cats[i], dir, sizeof dir);
        ensure_dir(dir, 0755);
    }
    log_info("%s categories ensured", lbl);
    return 0;
}

static int sweep_file_move(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_FILE_MOVE, lbl, sizeof lbl);
    log_sweep_start(lbl, "file movement starting");
    char **files = NULL;
    size_t file_count = 0, dir_count = 0;
    ScanState ss = {.ctx = ctx, .files_seen = 0, .dirs_seen = 0, .size_cap = ctx->size_cap_bytes};
    scan_directory_parallel(ctx->root, ctx->threads, dir_guard, file_guard, &ss, &files, &file_count, &dir_count);
    qsort(files, file_count, sizeof(char *), cmp_string_ptrs);
    size_t moved = 0;
    CategoryCounter *counters = NULL;
    size_t counter_count = 0, counter_cap = 0;
    for(size_t i=0;i<file_count;i++) {
        char base[NAME_MAX];
        path_basename(files[i], base, sizeof base);
        const char *cat = pick_category(base);
        char dest_base[NAME_MAX];
        if(ctx->enable_rename_files) {
            size_t idx = next_category_index(&counters, &counter_count, &counter_cap, cat);
            if(idx == 0) {
                log_warn("%s unable to allocate rename counter for %s", lbl, cat);
                free(files[i]);
                continue;
            }
            build_renamed_basename(cat, base, idx, dest_base, sizeof dest_base);
        } else {
            normalize_final_extension(base, dest_base, sizeof dest_base);
        }
        char dest_dir[PATH_MAX];
        path_join(ctx->root, cat, dest_dir, sizeof dest_dir);
        ensure_dir(dest_dir, 0755);
        char dest[PATH_MAX];
        path_join(dest_dir, dest_base, dest, sizeof dest);
        while(ctx->enable_rename_files && strcmp(files[i], dest)!=0 && access(dest, F_OK)==0) {
            size_t idx = next_category_index(&counters, &counter_count, &counter_cap, cat);
            if(idx == 0) break;
            build_renamed_basename(cat, base, idx, dest_base, sizeof dest_base);
            path_join(dest_dir, dest_base, dest, sizeof dest);
        }
        if(rename(files[i], dest)==0) {
            moved++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            log_live_status(lbl, rel);
        }
        free(files[i]);
    }
    free(counters);
    free(files);
    log_live_done();
    log_info("%s moved=%zu", lbl, moved);
    return 0;
}

static bool hashes_equal(const char *a, const char *b) {
    if(!a || !b) return false;
    char ha[65], hb[65];
    if(sha256_file(a, ha, sizeof ha)!=0) return false;
    if(sha256_file(b, hb, sizeof hb)!=0) return false;
    return strcmp(ha, hb)==0;
}

static int sweep_sanitize_underscores(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_SANITIZE_UNDERSCORES, lbl, sizeof lbl);
    log_sweep_start(lbl, "sanitize underscores starting");
    if(!ctx->enable_sanitize_underscores) {
        log_info("%s skipped (disabled)", lbl);
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
        if(rename(files[i], dest)==0) {
            renamed++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            log_live_status(lbl, rel);
            free(files[i]);
            continue;
        }
        if(errno==EEXIST || errno==ENOTEMPTY) {
            if(hashes_equal(files[i], dest)) {
                if(unlink(files[i])==0) {
                    dedup_removed++;
                    char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
                    log_live_status(lbl, rel);
                }
            } else {
                conflicts++;
                log_warn("%s conflict: %s -> %s exists with different content", lbl, files[i], dest);
            }
        } else {
            conflicts++;
            log_warn("%s rename failed %s -> %s (%s)", lbl, files[i], dest, strerror(errno));
        }
        free(files[i]);
    }
    free(files);
    log_live_done();
    log_info("%s renamed=%zu dedup_removed=%zu conflicts=%zu", lbl, renamed, dedup_removed, conflicts);
    return 0;
}

static int sweep_content_analysis(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_CONTENT_ANALYSIS, lbl, sizeof lbl);
    log_sweep_start(lbl, "content analysis starting");
    if(!ctx->enable_content_analysis) {
        strlist_free(&g_analysis_tokens);
        strlist_init(&g_analysis_tokens);
        log_info("%s skipped (disabled)", lbl);
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
        log_live_status(lbl, rel);
        free(files[i]);
    }
    free(files);
    log_live_done();
    strlist_dedupe(&g_analysis_tokens);
    log_info("%s refs=%zu unique_tokens=%zu", lbl, refs, g_analysis_tokens.count);
    return 0;
}

static int sweep_path_hash_dedup(SweepContext *ctx) {
    (void)ctx;
    char lbl[16]; sweep_label(SWEEP_PATH_HASH_DEDUP, lbl, sizeof lbl);
    log_sweep_start(lbl, "path hash dedup starting");
    if(g_analysis_tokens.count == 0) {
        log_info("%s skipped (no tokens)", lbl);
        return 0;
    }
    StrList hashes; strlist_init(&hashes);
    for(size_t i=0;i<g_analysis_tokens.count;i++) {
        const char *tok = g_analysis_tokens.items[i];
        char hex[65];
        if(sha256_bytes((const unsigned char*)tok, strlen(tok), hex, sizeof hex)) {
            strlist_append(&hashes, hex);
        }
    }
    strlist_dedupe(&hashes);
    log_info("%s tokens=%zu unique_hashes=%zu", lbl, g_analysis_tokens.count, hashes.count);
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

static bool is_text_refactor_category(const char *category) {
    if(!category) return false;
    return strcmp(category, "c")==0 ||
           strcmp(category, "javascript")==0 ||
           strcmp(category, "python")==0 ||
           strcmp(category, "ruby")==0 ||
           strcmp(category, "php")==0 ||
           strcmp(category, "markdown")==0 ||
           strcmp(category, "css")==0 ||
           strcmp(category, "json")==0 ||
           strcmp(category, "data")==0 ||
           strcmp(category, "template")==0 ||
           strcmp(category, "yml")==0 ||
           strcmp(category, "map")==0 ||
           strcmp(category, "html")==0 ||
           strcmp(category, "text")==0 ||
           strcmp(category, "code")==0;
}

static bool buffer_is_text(const char *buf, size_t len) {
    if(!buf) return false;
    for(size_t i=0;i<len;i++) {
        if(buf[i]=='\0') return false;
    }
    return true;
}

static bool write_file_atomic(const char *path, const char *buf, size_t len) {
    if(!path || !buf) return false;
    struct stat st;
    if(stat(path, &st)!=0 || !S_ISREG(st.st_mode)) return false;
    char dir[PATH_MAX];
    if(!path_dirname(path, dir, sizeof dir)) return false;
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s/.forensic-refactor-XXXXXX", dir);
    if(n < 0 || (size_t)n >= sizeof tmp) return false;
    int fd = mkstemp(tmp);
    if(fd < 0) return false;
    bool ok = fchmod(fd, st.st_mode & 07777)==0;
    size_t off = 0;
    while(ok && off < len) {
        ssize_t written = write(fd, buf + off, len - off);
        if(written < 0 && errno == EINTR) continue;
        if(written <= 0) { ok = false; break; }
        off += (size_t)written;
    }
    if(ok && fsync(fd)!=0) ok = false;
    if(close(fd)!=0) ok = false;
    if(ok && rename(tmp, path)==0) return true;
    unlink(tmp);
    return false;
}

static int sweep_path_refactor(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_PATH_REFACTOR, lbl, sizeof lbl);
    if(!ctx->enable_path_refactor) {
        log_info("%s path refactor skipped (disabled)", lbl);
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
        char base[NAME_MAX];
        path_basename(files[i], base, sizeof base);
        if(!is_text_refactor_category(pick_category(base))) {
            free(files[i]);
            continue;
        }
        char *buf=NULL; size_t len=0;
        int rc = read_file_limited(files[i], 512 * 1024, &buf, &len);
        if(rc!=0 || !buf) { free(files[i]); continue; }
        if(!buffer_is_text(buf, len)) { free(buf); free(files[i]); continue; }
        Replacement *repls = NULL; size_t repl_count=0, repl_cap=0;
        RefactorCtx rctx = {.ctx=ctx, .file_dir=dir, .repls=repls, .repl_count=&repl_count, .repl_cap=&repl_cap};
        scan_tokens(buf, len, refactor_token_handler, &rctx);
        if(repl_count>0) {
            if(apply_repls(&buf, &len, rctx.repls, repl_count)) {
                if(write_file_atomic(files[i], buf, len)) {
                    files_changed++;
                    replacements += repl_count;
                    char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
                    log_live_status(lbl, rel);
                }
            }
        }
        free(rctx.repls);
        free(buf);
        free(files[i]);
    }
    free(files);
    log_live_done();
    log_info("%s files_changed=%zu replacements=%zu", lbl, files_changed, replacements);
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
    log_info("%s cleanup done", lbl);
    return 0;
}

static int sweep_filename_pattern(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_FILENAME_PATTERN, lbl, sizeof lbl);
    log_sweep_start(lbl, "filename pattern dedup starting");
    if(ctx->enable_rename_files) {
        log_info("%s skipped (--rename enabled)", lbl);
        return 0;
    }
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
        if(sha256_file(files[i], hash, sizeof hash)!=0) { free(files[i]); continue; }
        PatternGroup *pg = pattern_group_get(sanitized, cat, true);
        if(!pg) { free(files[i]); continue; }
        bool dup=false;
        for(size_t j=0;j<pg->count;j++) {
            if(strcmp(pg->entries[j].hash, hash)==0) { dup=true; break; }
        }
        if(dup) {
            if(unlink(files[i])==0) {
                duplicates++;
                char rel[PATH_MAX]; sanitize_live_path(ctx, files[i], rel, sizeof rel);
                log_live_status(lbl, rel);
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
    log_live_done();
    log_info("%s duplicates_removed=%zu groups=%zu", lbl, duplicates, g_pattern_group_count);
    return 0;
}

static int sweep_pattern_groups(SweepContext *ctx) {
    char lbl[16]; sweep_label(SWEEP_PATTERN_GROUPS, lbl, sizeof lbl);
    log_sweep_start(lbl, "pattern grouping starting");
    if(ctx->enable_rename_files) {
        log_info("%s skipped (--rename enabled)", lbl);
        pattern_groups_reset();
        return 0;
    }
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
            normalize_final_extension(dest_name, dest_name, sizeof dest_name);
            char dest[PATH_MAX];
            if(!path_join(group_dir, dest_name, dest, sizeof dest)) continue;
        if(rename(pg->entries[j].path, dest)==0) {
            moved_total++;
            char rel[PATH_MAX]; sanitize_live_path(ctx, dest, rel, sizeof rel);
            log_live_status(lbl, rel);
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
    log_live_done();
    log_info("%s grouped_moves=%zu", lbl, moved_total);
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
    log_timing_summary(sweeps, durations, ran, count, total_seconds);
    if(rc!=0) return rc;
    return 0;
}

int run_prewarm(SweepContext *ctx) { (void)ctx; return 0; }
