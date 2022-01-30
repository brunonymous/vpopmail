#ifndef __CACHE_H_
   #define __CACHE_H_

#include "conf.h"

int cache_init(config_t *);
void *cache_lookup(const char *);
int cache_add(const char *, const void *);
void cache_remove(const char *);

#endif
