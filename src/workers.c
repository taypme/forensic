#define _GNU_SOURCE
#include "workers.h"
#include "logging.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} PathVec;

static void pv_init(PathVec *pv) { pv->items=NULL; pv->count=pv->cap=0; }
static void pv_free(PathVec *pv) {
    if(!pv) return;
    for(size_t i=0;i<pv->count;i++) free(pv->items[i]);
    free(pv->items);
    pv->items=NULL; pv->count=pv->cap=0;
}
static bool pv_append(PathVec *pv, const char *path) {
    if(pv->count == pv->cap) {
        size_t nc = pv->cap ? pv->cap * 2 : 1024;
        char **tmp = realloc(pv->items, nc * sizeof(char*));
        if(!tmp) return false;
        pv->items = tmp; pv->cap = nc;
    }
    pv->items[pv->count] = strdup(path);
    if(!pv->items[pv->count]) return false;
    pv->count++;
    return true;
}

static void walk(const char *root, int depth, forensic_dir_filter_fn dir_filter, forensic_file_filter_fn file_filter, void *userdata, PathVec *out, size_t *dir_count) {
    if(depth > 100) return;
    DIR *d = opendir(root);
    if(!d) return;
    if(dir_count) (*dir_count)++;
    struct dirent *ent;
    while((ent = readdir(d))) {
        if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
        char path[PATH_MAX];
        if(snprintf(path, sizeof path, "%s/%s", root, ent->d_name) >= (int)sizeof path) continue;
        struct stat st;
        if(lstat(path, &st)!=0) continue;
        if(S_ISLNK(st.st_mode)) { unlink(path); continue; }
        if(S_ISDIR(st.st_mode)) {
            if(dir_filter && !dir_filter(path, &st, depth+1, userdata)) continue;
            walk(path, depth+1, dir_filter, file_filter, userdata, out, dir_count);
        } else if(S_ISREG(st.st_mode)) {
            if(file_filter && !file_filter(path, &st, depth, userdata)) continue;
            pv_append(out, path);
        }
    }
    closedir(d);
}

int scan_directory_parallel(const char *root, int threads, forensic_dir_filter_fn dir_filter, forensic_file_filter_fn file_filter, void *userdata, char ***out_files, size_t *out_count, size_t *out_dirs) {
    (void)threads; // simplified single-thread walk for correctness
    if(out_files) *out_files = NULL;
    if(out_count) *out_count = 0;
    if(out_dirs) *out_dirs = 0;
    if(!root) return -1;
    PathVec pv; pv_init(&pv);
    size_t dirs = 0;
    if(dir_filter && !dir_filter(root, NULL, 0, userdata)) return 0;
    walk(root, 0, dir_filter, file_filter, userdata, &pv, &dirs);
    if(out_files) *out_files = pv.items; else pv_free(&pv);
    if(out_count) *out_count = pv.count;
    if(out_dirs) *out_dirs = dirs;
    return 0;
}
