#include "sha256.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static void to_hex(const unsigned char *digest, size_t len, char *out, size_t out_sz) {
    static const char *hex = "0123456789abcdef";
    if(out_sz < len*2 + 1) return;
    for(size_t i=0;i<len;i++) {
        out[i*2] = hex[(digest[i] >> 4) & 0xF];
        out[i*2+1] = hex[digest[i] & 0xF];
    }
    out[len*2] = '\0';
}

int sha256_file(const char *path, char *out_hex, size_t out_hex_sz) {
    if(!path || !out_hex || out_hex_sz < 65) return -1;
    unsigned char buf[65536];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    FILE *f = fopen(path, "rb");
    if(!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) { fclose(f); return -1; }
    const EVP_MD *md = EVP_sha256();
    if(EVP_DigestInit_ex(ctx, md, NULL)!=1) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    size_t r;
    while((r = fread(buf,1,sizeof buf,f))>0) {
        if(EVP_DigestUpdate(ctx, buf, r)!=1) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    }
    fclose(f);
    if(EVP_DigestFinal_ex(ctx, digest, &dlen)!=1) { EVP_MD_CTX_free(ctx); return -1; }
    EVP_MD_CTX_free(ctx);
    to_hex(digest, dlen, out_hex, out_hex_sz);
    return 0;
}
