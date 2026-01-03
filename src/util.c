#include "util.h"
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

bool ensure_dir(const char *path, int mode) {
    if(!path) return false;
    struct stat st;
    if(stat(path, &st)==0) return S_ISDIR(st.st_mode);
    if(errno == ENOENT) {
        // Try to create parent directories first
        char parent[PATH_MAX];
        if(path_dirname(path, parent, sizeof parent)) {
            // Only recurse if parent is different and not "." or "/"
            if(strcmp(parent, path) != 0 && strcmp(parent, ".") != 0 && strcmp(parent, "/") != 0) {
                ensure_dir(parent, mode);
            }
        }
        if(mkdir(path, mode)==0) return true;
        // If mkdir failed, check if it exists now (race condition or already created)
        if(stat(path, &st)==0 && S_ISDIR(st.st_mode)) return true;
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

bool copy_file(const char *src, const char *dst) {
    if(!src || !dst) return false;
    
    // Get source file stats to preserve permissions
    struct stat st;
    if(stat(src, &st) != 0) return false;
    if(!S_ISREG(st.st_mode)) return false;
    
    // Ensure destination directory exists
    char dst_dir[PATH_MAX];
    if(!path_dirname(dst, dst_dir, sizeof dst_dir)) return false;
    if(!ensure_dir(dst_dir, 0755)) return false;
    
    // Open source file
    FILE *src_fp = fopen(src, "rb");
    if(!src_fp) return false;
    
    // Open destination file
    FILE *dst_fp = fopen(dst, "wb");
    if(!dst_fp) {
        fclose(src_fp);
        return false;
    }
    
    // Copy file contents
    char buffer[8192];
    size_t bytes_read;
    bool success = true;
    while((bytes_read = fread(buffer, 1, sizeof buffer, src_fp)) > 0) {
        if(fwrite(buffer, 1, bytes_read, dst_fp) != bytes_read) {
            success = false;
            break;
        }
    }
    
    fclose(src_fp);
    if(fclose(dst_fp) != 0) success = false;
    
    // Preserve file permissions
    if(success && chmod(dst, st.st_mode & 0777) != 0) {
        // Non-fatal, but log if needed
        success = false;
    }
    
    return success;
}
