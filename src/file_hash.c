#include "file_hash.h"
#include "sha256.h"
#include "logging.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static int read_char_at(int fd, off_t offset, char *out) {
    if(lseek(fd, offset, SEEK_SET) == (off_t)-1) return -4;
    ssize_t r = read(fd, out, 1);
    if(r != 1) return -4;
    return 0;
}

static int hash_file_sparse(int fd, off_t size, char *out_hex, size_t out_sz) {
    if(out_sz < 65) return -3;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    char ch;
    if(size > 0) {
        if(read_char_at(fd, 0, &ch) != 0) return -4;
        sha256_update(&ctx, (const unsigned char*)&ch, 1);
    }
    for(off_t pos = 64; pos < size - 1; pos += 64) {
        if(read_char_at(fd, pos, &ch) != 0) return -4;
        sha256_update(&ctx, (const unsigned char*)&ch, 1);
    }
    if(size > 1) {
        if(read_char_at(fd, size - 1, &ch) != 0) return -4;
        sha256_update(&ctx, (const unsigned char*)&ch, 1);
    }
    unsigned char digest[32];
    sha256_final(&ctx, digest);
    for(int i=0;i<32;i++) sprintf(out_hex + i*2, "%02x", digest[i]);
    out_hex[64]='\0';
    return 0;
}

static int hash_file_full(int fd, off_t size, char *out_hex, size_t out_sz) {
    if(out_sz < 65) return -3;
    size_t sz = (size_t)size;
    SHA256_CTX ctx; sha256_init(&ctx);
    const size_t MMAP_THRESHOLD = 1<<20; // 1MB
    if(sz > MMAP_THRESHOLD) {
        void *map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if(map == MAP_FAILED) { log_warn("mmap failed; falling back to read"); }
        else {
            sha256_update(&ctx, (const unsigned char*)map, sz);
            munmap(map, sz);
        }
    }
    if(ctx.buffer_len == 0 && sz <= MMAP_THRESHOLD) {
        unsigned char buf[65536]; ssize_t r;
        while((r = read(fd, buf, sizeof buf)) > 0) sha256_update(&ctx, buf, (size_t)r);
    } else if(sz <= MMAP_THRESHOLD) {
        // Already processed? (should not happen) fallback read remaining
        unsigned char buf[4096]; ssize_t r; while((r=read(fd,buf,sizeof buf))>0) sha256_update(&ctx, buf, (size_t)r);
    }
    unsigned char digest[32]; sha256_final(&ctx, digest);
    for(int i=0;i<32;i++) sprintf(out_hex + i*2, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

int hash_file(const char *path, char *out_hex, size_t out_sz) {
    if(out_sz < 65) return -3; // insufficient buffer
    int fd = open(path, O_RDONLY);
    if(fd < 0) { log_error("open failed for %s", path); return -1; }
    struct stat st; if(fstat(fd, &st) != 0) { close(fd); return -2; }
    int rc = hash_file_sparse(fd, st.st_size, out_hex, out_sz);
    if(rc != 0) {
        if(lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            close(fd);
            return rc;
        }
        rc = hash_file_full(fd, st.st_size, out_hex, out_sz);
    }
    close(fd);
    return rc;
}
