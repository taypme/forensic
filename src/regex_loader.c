#define _DEFAULT_SOURCE
#include "regex_loader.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static char *trim_line(char *s) {
    size_t n = strlen(s);
    while(n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) s[--n]='\0';
    while(*s==' ' || *s=='\t') s++;
    return s;
}

static int is_regular_file(const char *path) {
    struct stat st;
    if(stat(path,&st)!=0) return 0;
    return S_ISREG(st.st_mode);
}

static const char *default_paths_patterns[] = {
    "/([A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+\\.[A-Za-z0-9._-]+",
    "(\\.\\./)+[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*",
    "(\\./)?[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*",
    "[A-Za-z]:[\\\\/]+([^\\\\/:*?\\\"<>|]+[\\\\/]+)+[^\\\\/:*?\\\"<>|]+",
    "~/([A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+\\.[A-Za-z0-9._-]+",
    "\\\"((\\.\\.?|~)/)?[^\\\"]+/[A-Za-z0-9._-]+\\.[A-Za-z0-9._-]+\\\"",
    "'((\\.\\.?/)|/|~)[^']+/[A-Za-z0-9._-]+\\.[A-Za-z0-9._-]+'",
    "\\\"((https?|git)://)?[A-Za-z0-9._-]+/[A-Za-z0-9._@:/-]+\\.[A-Za-z0-9._-]+\\\"",
    "url\\([[:space:]]*['\\\"]?/[A-Za-z0-9._/?&=%#@:+-]+['\\\"]?[[:space:]]*\\)",
    "url\\([[:space:]]*['\\\"]*(\\.\\./?)+[A-Za-z0-9._/?&=%#@:+-]+['\\\"]*[[:space:]]*\\)",
    "\\\"github\\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\\\"",
    "\\\"golang\\.org/x/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*\\\"",
    "\\\"(\\.\\./)*internal(/[A-Za-z0-9._-]+)+\\\"",
    "['\\\"](\\.\\./|/)[A-Za-z0-9._/-]+\\.(php|inc)['\\\"]",
    "__DIR__[[:space:]]*\\.[[:space:]]*['\\\"/\\\\]+[A-Za-z0-9._/-]+\\.(php|inc)",
    "(require_once|require)[[:space:]]*\\([[:space:]]*['\\\"][A-Za-z0-9._/-]+\\.(php|phtml)['\\\"][[:space:]]*\\)",
    "['\\\"](\\.\\./|/)[A-Za-z0-9._/-]+\\.(py|pyi)['\\\"]",
    "os\\.path\\.join\\([^)]*['\\\"][A-Za-z0-9._/-]+['\\\"]\\)",
    "open\\([[:space:]]*['\\\"][A-Za-z0-9._/-]+\\.(py|txt|cfg)['\\\"][[:space:]]*\\)",
    "['\\\"](\\.\\./|/)[A-Za-z0-9._/-]+\\.(rb|rake)['\\\"]",
    "File\\.join\\([^)]*['\\\"][A-Za-z0-9._/-]+['\\\"]\\)",
    "require_relative[[:space:]]+['\\\"][A-Za-z0-9._/-]+['\\\"]",
    "require\\([[:space:]]*['\\\"][A-Za-z0-9._/@-]+(/[A-Za-z0-9._-]+)+\\.(js|json)['\\\"][[:space:]]*\\)",
    "import[[:space:]]+[^;]*[[:space:]]+from[[:space:]]+['\\\"][A-Za-z0-9._/@-]+(/[A-Za-z0-9._-]+)+['\\\"]",
    "path\\.join\\([^)]*['\\\"][A-Za-z0-9._/-]+['\\\"]\\)"
};

static RegexRegistry *regex_registry_from_defaults(void) {
    RegexRegistry *rr = (RegexRegistry*)calloc(1,sizeof *rr);
    if(!rr) return NULL;
    RegexEntry *entry = (RegexEntry*)calloc(1, sizeof *entry);
    if(!entry){ free(rr); return NULL; }
    rr->entries = entry; rr->count = 1;
    snprintf(entry->key, sizeof entry->key, "%s", "paths.regex");
    entry->count = sizeof(default_paths_patterns)/sizeof(default_paths_patterns[0]);
    entry->patterns = (char**)calloc(entry->count, sizeof(char*));
    if(!entry->patterns){ free(entry); free(rr); return NULL; }
    for(size_t i=0;i<entry->count;i++){
        const char *p = default_paths_patterns[i];
        size_t len = strlen(p);
        entry->patterns[i] = (char*)malloc(len+1);
        if(entry->patterns[i]) memcpy(entry->patterns[i], p, len+1);
    }
    return rr;
}

RegexRegistry *regex_registry_load(const char *root) {
    char dirp[PATH_MAX];
    snprintf(dirp,sizeof dirp,"%s/regex", root);
    DIR *d = opendir(dirp);
    if(!d) return regex_registry_from_defaults();
    RegexRegistry *rr = (RegexRegistry*)calloc(1,sizeof *rr);
    if(!rr){ closedir(d); return NULL; }
    struct dirent *ent;
    while((ent=readdir(d))) {
        if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0) continue;
        char path[PATH_MAX];
        size_t dir_len = strlen(dirp);
        size_t name_len = strlen(ent->d_name);
        if(dir_len + 1 >= sizeof path) continue;
        memcpy(path, dirp, dir_len);
        path[dir_len] = '/';
        size_t avail = sizeof path - dir_len - 1;
        if(name_len > avail) name_len = avail;
        memcpy(path + dir_len + 1, ent->d_name, name_len);
        path[dir_len + 1 + name_len] = '\0';
        if(!is_regular_file(path)) continue;
        FILE *f = fopen(path,"r");
        if(!f) continue;
        char **patterns=NULL; size_t cap=0,count=0;
        char line[2048];
        while(fgets(line,sizeof line,f)) {
            char *p = trim_line(line);
            if(*p=='\0' || *p=='#') continue;
            size_t len=strlen(p);
            char *dup=(char*)malloc(len+1);
            if(!dup) continue;
            memcpy(dup,p,len+1);
            if(count==cap){
                size_t ncap=cap?cap*2:8;
                char **nb=(char**)realloc(patterns,ncap*sizeof(char*));
                if(!nb){ free(dup); continue; }
                patterns=nb; cap=ncap;
            }
            patterns[count++]=dup;
        }
        fclose(f);
        if(count==0){
            for(size_t i=0;i<count;i++) free(patterns[i]);
            free(patterns);
            continue;
        }
        RegexEntry *ne=(RegexEntry*)realloc(rr->entries,(rr->count+1)*sizeof *ne);
        if(!ne){
            for(size_t i=0;i<count;i++) free(patterns[i]);
            free(patterns);
            continue;
        }
        rr->entries=ne;
        RegexEntry *slot=&rr->entries[rr->count++];
        memset(slot,0,sizeof *slot);
        size_t key_len = strlen(ent->d_name);
        if(key_len >= sizeof slot->key) key_len = sizeof slot->key - 1;
        memcpy(slot->key, ent->d_name, key_len);
        slot->key[key_len] = '\0';
        slot->patterns=patterns;
        slot->count=count;
    }
    closedir(d);
    if(rr->count==0) {
        regex_registry_free(rr);
        return regex_registry_from_defaults();
    }
    return rr;
}

void regex_registry_free(RegexRegistry *rr) {
    if(!rr) return;
    for(size_t i=0;i<rr->count;i++) {
        for(size_t j=0;j<rr->entries[i].count;j++) free(rr->entries[i].patterns[j]);
        free(rr->entries[i].patterns);
    }
    free(rr->entries);
    free(rr);
}

const RegexEntry *regex_registry_find(const RegexRegistry *rr, const char *key) {
    if(!rr || !key) return NULL;
    for(size_t i=0;i<rr->count;i++) if(strcmp(rr->entries[i].key,key)==0) return &rr->entries[i];
    return NULL;
}
