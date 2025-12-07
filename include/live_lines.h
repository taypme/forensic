#ifndef FORENSIC_LIVE_LINES_H
#define FORENSIC_LIVE_LINES_H

void live_begin(const char *label);
void live_update(const char *item);
void live_end(void);
void live_set_root(const char *root);

#endif
