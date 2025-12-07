#include "redis.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

static int g_fd = -1; static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER; static int g_ok = 0;

static int connect_redis(const char *host, int port){
    int fd = socket(AF_INET, SOCK_STREAM, 0); if(fd<0) return -1;
    int one=1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in addr; memset(&addr,0,sizeof addr); addr.sin_family=AF_INET; addr.sin_port=htons(port);
    if(inet_pton(AF_INET, host, &addr.sin_addr)!=1){ close(fd); return -2; }
    if(connect(fd,(struct sockaddr*)&addr,sizeof addr)!=0){ close(fd); return -3; }
    return fd;
}

int redis_init(const char *host, int port){
    g_fd = connect_redis(host, port);
    g_ok = (g_fd >= 0);
    if(!g_ok) log_warn("redis unavailable; degraded mode (in-memory only)");
    return g_ok?0:-1;
}

bool redis_available(void){ return g_ok!=0; }

// Minimal RESP helpers
static int send_all(int fd, const char *buf, size_t len){ size_t off=0; while(off<len){ ssize_t w=write(fd,buf+off,len-off); if(w<=0) return -1; off+= (size_t)w; } return 0; }
static int read_line(int fd, char *buf, size_t max){ size_t off=0; while(off+1<max){ ssize_t r=read(fd,buf+off,1); if(r<=0) return -1; if(buf[off]=='\n'){ buf[off+1]='\0'; return 0; } off++; } return -2; }

int redis_set(const char *key, const char *val){
    if(!redis_available()) return 0; // silently succeed when degraded
    pthread_mutex_lock(&g_mtx);
    char cmd[1024]; int n = snprintf(cmd, sizeof cmd, "*3\r\n$3\r\nSET\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n", strlen(key), key, strlen(val), val);
    if(n<=0 || (size_t)n >= sizeof cmd){ pthread_mutex_unlock(&g_mtx); return -2; }
    if(send_all(g_fd, cmd, (size_t)n)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -3; }
    char line[256]; if(read_line(g_fd,line,sizeof line)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -4; }
    pthread_mutex_unlock(&g_mtx);
    if(line[0]=='+' || line[0]=='$' || strncmp(line,"$-1",3)==0) return 0; // OK or nil
    return -5;
}

int redis_get(const char *key, char *buf, size_t buflen){
    if(!redis_available()) return -1;
    pthread_mutex_lock(&g_mtx);
    char cmd[512]; int n = snprintf(cmd, sizeof cmd, "*2\r\n$3\r\nGET\r\n$%zu\r\n%s\r\n", strlen(key), key);
    if(n<=0 || (size_t)n >= sizeof cmd){ pthread_mutex_unlock(&g_mtx); return -2; }
    if(send_all(g_fd, cmd, (size_t)n)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -3; }
    char line[1024]; if(read_line(g_fd,line,sizeof line)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -4; }
    if(line[0]=='$'){ long len = strtol(line+1,NULL,10); if(len==-1){ pthread_mutex_unlock(&g_mtx); return -6; } if((size_t)len >= buflen) len = (long)buflen-1; size_t want = (size_t)len + 2; size_t off=0; while(off < want){ ssize_t r=read(g_fd, buf+off, want-off); if(r<=0){ pthread_mutex_unlock(&g_mtx); return -7; } off += (size_t)r; } buf[len]='\0'; pthread_mutex_unlock(&g_mtx); return 0; }
    pthread_mutex_unlock(&g_mtx); return -5;
}

int redis_get_alloc(const char *key, char **out, size_t *out_len){
    if(out) *out = NULL;
    if(out_len) *out_len = 0;
    if(!redis_available() || !out) return -1;
    pthread_mutex_lock(&g_mtx);
    char cmd[512]; int n = snprintf(cmd, sizeof cmd, "*2\r\n$3\r\nGET\r\n$%zu\r\n%s\r\n", strlen(key), key);
    if(n<=0 || (size_t)n >= sizeof cmd){ pthread_mutex_unlock(&g_mtx); return -2; }
    if(send_all(g_fd, cmd, (size_t)n)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -3; }
    char line[1024]; if(read_line(g_fd,line,sizeof line)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -4; }
    if(line[0]!='$'){ pthread_mutex_unlock(&g_mtx); return -5; }
    long len = strtol(line+1,NULL,10);
    if(len == -1){ pthread_mutex_unlock(&g_mtx); return -6; }
    if(len < 0 || len > 1024*1024*512) { pthread_mutex_unlock(&g_mtx); return -7; }
    size_t want = (size_t)len + 2; // include trailing CRLF
    size_t alloc = want + 1; // null terminator
    char *buf = (char*)malloc(alloc);
    if(!buf){ pthread_mutex_unlock(&g_mtx); return -8; }
    size_t off=0;
    while(off < want){
        ssize_t r = read(g_fd, buf + off, want - off);
        if(r<=0){ free(buf); pthread_mutex_unlock(&g_mtx); return -9; }
        off += (size_t)r;
    }
    pthread_mutex_unlock(&g_mtx);
    buf[len] = '\0';
    if(out_len) *out_len = (size_t)len;
    *out = buf;
    return 0;
}

int redis_append(const char *key, const char *val){
    if(!redis_available()) return 0;
    size_t keylen = strlen(key), vallen = strlen(val);
    size_t cap = keylen + vallen + 128;
    char *cmd = (char*)malloc(cap);
    if(!cmd) return -2;
    int n = snprintf(cmd, cap, "*3\r\n$6\r\nAPPEND\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n", keylen, key, vallen, val);
    if(n <= 0 || (size_t)n >= cap) { free(cmd); return -3; }
    pthread_mutex_lock(&g_mtx);
    if(send_all(g_fd, cmd, (size_t)n)!=0){ pthread_mutex_unlock(&g_mtx); free(cmd); g_ok=0; return -4; }
    free(cmd);
    char line[256];
    if(read_line(g_fd, line, sizeof line)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -5; }
    pthread_mutex_unlock(&g_mtx);
    return (line[0]==':' || line[0]=='+') ? 0 : -6;
}

int redis_flushall(void){
    if(!redis_available()) return -1;
    const char *cmd="*1\r\n$8\r\nFLUSHALL\r\n";
    pthread_mutex_lock(&g_mtx);
    if(send_all(g_fd, cmd, strlen(cmd))!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -2; }
    char line[256];
    if(read_line(g_fd, line, sizeof line)!=0){ pthread_mutex_unlock(&g_mtx); g_ok=0; return -3; }
    pthread_mutex_unlock(&g_mtx);
    return (line[0]=='+' || line[0]==':') ? 0 : -4;
}
