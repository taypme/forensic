#include "util.h"
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

bool ensure_dir(const char *path, int mode) {
    struct stat st;
    if(stat(path, &st)==0) return S_ISDIR(st.st_mode);
    if(errno == ENOENT) {
        if(mkdir(path, mode)==0) return true;
    }
    return false;
}

bool path_join(const char *a, const char *b, char *out, size_t out_sz) {
    if(!a || !b || !out || out_sz==0) return false;
    int n = snprintf(out, out_sz, "%s/%s", a, b);
    return n > 0 && (size_t)n < out_sz;
}

bool path_basename(const char *path, char *out, size_t out_sz) {
    if(!path || !out || out_sz==0) return false;
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    size_t len = strlen(base);
    if(len >= out_sz) len = out_sz - 1;
    memcpy(out, base, len);
    out[len] = '\0';
    return true;
}

bool path_dirname(const char *path, char *out, size_t out_sz) {
    if(!path || !out || out_sz==0) return false;
    const char *slash = strrchr(path, '/');
    if(!slash) {
        if(out_sz < 2) return false;
        strcpy(out, ".");
        return true;
    }
    size_t len = (size_t)(slash - path);
    if(len == 0) len = 1;
    if(len >= out_sz) len = out_sz - 1;
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

bool normalize_root(char *path) {
    if(!path) return false;
    size_t len = strlen(path);
    while(len>1 && path[len-1]=='/') { path[len-1]='\0'; len--; }
    return true;
}
