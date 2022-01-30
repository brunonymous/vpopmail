#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "conf.h"
#include "uthash.h"
#include "cache.h"

/*
   Hash table
*/

typedef struct __item_ {
   char *key;
   void *ptr;
   UT_hash_handle hh;
} item_t;

item_t *cache = NULL;

/*
   Configure caching system
*/

int cache_init(config_t *config)
{
   cache = NULL;
   return 1;
}

/*
   Add an item to the cache
*/

int cache_add(const char *key, const void *ptr)
{
   char *p = NULL;
   item_t *i = NULL;

#ifdef ASSERT_DEBUG
   assert(key != NULL);
   assert(ptr != NULL);
#endif

   i = malloc(sizeof(item_t));
   if (i == NULL) {
	  fprintf(stderr, "cache_add: malloc failed\n");
	  return 0;
   }

   memset(i, 0, sizeof(item_t));

   i->key = strdup(key);
   if (i->key == NULL) {
	  fprintf(stderr, "cache_add: strdup failed\n");
	  return 0;
   }

   for (p = i->key; *p; p++) {
	  if ((*p >= 'A') && (*p <= 'Z'))
		 *p = tolower(*p);
   }

   i->ptr = (void *)ptr;

   HASH_ADD_KEYPTR(hh, cache, i->key, strlen(i->key), i);

#ifdef CACHE_DEBUG
   printf("cache: Added %p as %s\n", ptr, key);
#endif

   return 1;
}

/*
   Lookup a cached item
*/

void *cache_lookup(const char *key)
{
   item_t *i = NULL;

#ifdef ASSERT_DEBUG
   assert(key != NULL);
#endif

   HASH_FIND(hh, cache, key, strlen(key), i);

#ifdef CACHE_DEBUG
   if (i)
	  printf("cache: Found %p at %s\n", i->ptr, key);
   else
	  printf("cache: Not found: %s\n", key);
#endif

   if (i)
	  return i->ptr;

   return NULL;
}

/*
   Remove a cached item
*/

void cache_remove(const char *key)
{
   item_t *i = NULL;

#ifdef ASSERT_DEBUG
   assert(key != NULL);
#endif

   HASH_FIND(hh, cache, key, strlen(key), i);

   if (i) {
#ifdef CACHE_DEBUG
	  printf("cache: Deleting %p at %s\n", i->ptr, key);
#endif
	  HASH_DEL(cache, i);
   }

#ifdef CACHE_DEBUG
   else
	  printf("cache: Nothing to delete at %s\n", key);
#endif
}
