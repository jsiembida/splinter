
/******************************************/

#include "splinter.h"

/******************************************/

/*
 * Not thread-safe, meant to be used from a single,
 * worker thread. Otherwise, all synchronization
 * has to be ensured at an upper layer.
 */

static hook_p __hooks_buffer = NULL;
static hook_p __hooks_free = NULL;
static hook_p __hooks_limbo = NULL;

uint_t stats_hooks_total = 0;
uint_t stats_hooks_free = 0;
uint_t stats_hooks_used = 0;
uint_t stats_hooks_limbo = 0;
uint_t stats_hooks_total_bytes = 0;
uint_t stats_hooks_free_bytes = 0;
uint_t stats_hooks_used_bytes = 0;
uint_t stats_hooks_limbo_bytes = 0;

static trigger_t __hook_alloc_trigger = NULL;
static trigger_t __hook_free_trigger = NULL;

static void __hook_free(hook_p h) {
  uint32_t id;
  DEBUG("freeing hook = %p", h);
  atom_free(h->entry_chain);
  atom_free(h->exit_chain);
  id = h->id;
  memset(h, 0, hook_s);
  h->id = id;
  h->next = __hooks_free;
  __hooks_free = h;
  stats_hooks_free += 1;
  stats_hooks_free_bytes += hook_s;
  if (__hook_free_trigger) __hook_free_trigger();
}


static int __hooks_gc(void) {
  int still_in_limbo = 0;
  hook_p prev = NULL;
  hook_p curr = __hooks_limbo;
  hook_p temp;
  while(curr) {
    DEBUG("hook = %p refcount = %u", curr, curr->refcount);
    if (curr->refcount == 0) {
      temp = curr->next;
      if (curr == __hooks_limbo)
        __hooks_limbo = temp;
      if (prev)
        prev->next = temp;
      __hook_free(curr);
      curr = temp;
      stats_hooks_limbo -= 1;
      stats_hooks_limbo_bytes -= hook_s;
    } else {
      still_in_limbo++;
      prev = curr;
      curr = curr->next;
    }
  }
  return still_in_limbo;
}


int hooks_init(uint_t n, trigger_t alloc_trigger, trigger_t free_trigger) {
  int i;
  hook_p curr_hook;

  debug(DEBUG_INF, "size = %lu", n);

  if (!n) return hooks_cleanup();
  if (__hooks_buffer) return -1;

  if ((__hooks_buffer = splinter_memory_alloc(n * hook_s)) == NULL) {
    debug(DEBUG_ERR, "could not alloc hooks buffer");
    return -1;
  }
  for(i = 0, curr_hook = __hooks_buffer; i < n - 1; i++, curr_hook++) {
    curr_hook->id = i + 1;
    curr_hook->next = curr_hook + 1;
  }
  curr_hook->id = i + 1;

  __hooks_free = __hooks_buffer;
  stats_hooks_total = stats_hooks_free = n;
  stats_hooks_total_bytes = stats_hooks_free_bytes = n * hook_s;
  stats_hooks_used = stats_hooks_used_bytes = 0;
  __hooks_limbo = NULL;
  stats_hooks_limbo = stats_hooks_limbo_bytes = 0;

  __hook_alloc_trigger = alloc_trigger;
  __hook_free_trigger = free_trigger;

  debug(DEBUG_DBG, "hooks buffer = %p - %p", __hooks_buffer, ((byte_p)__hooks_buffer) + n * hook_s);

  return 0;
}


int hooks_cleanup() {
  DEBUG();

  if (!__hooks_buffer) return -1;
  if (__hooks_gc()) return -1;
  if (stats_hooks_free != stats_hooks_total) return -1;

  memset(__hooks_buffer, 0, hook_s * stats_hooks_total);
  __hooks_free = __hooks_limbo = __hooks_buffer =
    splinter_memory_free(__hooks_buffer);
  stats_hooks_total = stats_hooks_free = stats_hooks_used = stats_hooks_limbo = 0;
  stats_hooks_total_bytes = stats_hooks_free_bytes =
    stats_hooks_used_bytes = stats_hooks_limbo_bytes = 0;

  __hook_alloc_trigger = NULL;
  __hook_free_trigger = NULL;

  return 0;
}


int hook_in_use(hook_p h) {
  hook_p i;
  DEBUG();
  if (!h) return 0;
  for(i = __hooks_free; i; i = i->next)
    if (i == h) return 0;
  for(i = __hooks_limbo; i; i = i->next)
    if (i == h) return 0;
  return 1;
}


hook_p hook_get(uint_t i) {
  DEBUG();
  if (!__hooks_buffer) return NULL;
  __hooks_gc();
  if (i == 0 || i > stats_hooks_total) return NULL;
  return __hooks_buffer + i - 1;
}


hook_p hook_find(uint_t address) {
  int i;
  DEBUG();
  if (!__hooks_buffer || !address) return NULL;
  __hooks_gc();
  for(i = 0; i < stats_hooks_total; i++) {
    if (__hooks_buffer[i].address == address) return __hooks_buffer + i;
  }
  return NULL;
}


hook_p hook_alloc() {
  hook_p h;
  DEBUG();
  if (!__hooks_buffer) return NULL;
  __hooks_gc();
  if ((h = __hooks_free) != NULL) {
    __hooks_free = h->next;
    stats_hooks_free -= 1;
    stats_hooks_free_bytes -= hook_s;
    stats_hooks_used += 1;
    stats_hooks_used_bytes += hook_s;
    if (__hook_alloc_trigger) __hook_alloc_trigger();
  }
  DEBUG("allocating hook = %p", h);
  return h;
}


hook_p hook_free(hook_p h) {
  DEBUG();
  if (!h || !__hooks_buffer) return NULL;
  __hooks_gc();
  h->address = 0;
  h->enabled = 0;
  stats_hooks_used -= 1;
  stats_hooks_used_bytes -= hook_s;
  if (h->refcount == 0) {
    __hook_free(h);
  } else {
    debug(DEBUG_INF, "sending %p to limbo", h);
    h->next = __hooks_limbo;
    __hooks_limbo = h;
    stats_hooks_limbo += 1;
    stats_hooks_limbo_bytes += hook_s;
  }
  return NULL;
}
