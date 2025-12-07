#include "sweep_services.h"
#include "logging.h"
#include "sha256.h"
#include "util.h"
#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>

static int ensure_dir_int(const char *path, int mode) {
    return ensure_dir(path, mode) ? 0 : -1;
}

static int path_join_int(const char *a, const char *b, char *out, size_t out_sz) {
    return path_join(a, b, out, out_sz) ? 0 : -1;
}

static int hash_bytes_default(const unsigned char *data, size_t len, char *out_hex, size_t out_hex_sz) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return -1;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)==1 &&
              EVP_DigestUpdate(ctx, data, len)==1 &&
              EVP_DigestFinal_ex(ctx, digest, &dlen)==1;
    EVP_MD_CTX_free(ctx);
    if(!ok) return -1;
    static const char *hex = "0123456789abcdef";
    if(out_hex_sz < dlen*2 + 1) return -1;
    for(unsigned int i=0;i<dlen;i++) {
        out_hex[i*2] = hex[(digest[i] >> 4) & 0xF];
        out_hex[i*2+1] = hex[digest[i] & 0xF];
    }
    out_hex[dlen*2] = '\0';
    return 0;
}

const SweepServices g_sweep_services_default = {
    .log_info = log_info,
    .log_warn = log_warn,
    .log_error = log_error,
    .log_debug = log_debug,
    .log_live_status = log_live_status,
    .log_live_done = log_live_done,
    .hash_file = sha256_file,
    .hash_bytes = hash_bytes_default,
    .rename_fn = rename,
    .unlink_fn = unlink,
    .ensure_dir = ensure_dir_int,
    .path_join = path_join_int,
};
