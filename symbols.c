
/******************************************/

#include "splinter.h"

/******************************************/

#define SYMBOLS_NAME_LENGTH (64 - sizeof(void *) - uint_s - 1)

struct __symbol_t {
  struct __symbol_t * next;
  uint_t address;
  char name[SYMBOLS_NAME_LENGTH + 1];
};

typedef struct __symbol_t symbol_t;
typedef symbol_t * symbol_p;
#define symbol_s sizeof(symbol_t)

uint_t stats_symbols_total;
uint_t stats_symbols_free;
uint_t stats_symbols_used;
uint_t stats_symbols_total_bytes;
uint_t stats_symbols_free_bytes;
uint_t stats_symbols_used_bytes;

uint_t stats_symbols_hash_size;
uint_t stats_symbols_hash_bytes;

static symbol_p __symbols_buffer = NULL;
static symbol_p __symbols_free = NULL;

#define SYMBOLS_HASH_LENGTH 256
static symbol_p __symbols_hashtable[SYMBOLS_HASH_LENGTH];

//
// A naive java.lang.String hash implementation in C
// s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
//

static uint_t __string_hash(char * s) {
  char * r;
  uint_t h = 0, x = 1, len = strlen(s);
  for(r = s + len - 1; r >= s; x *= 31)
    h += ((uint_t)(*r--)) * x;
  return h;
}

static symbol_p * __symbol_find(char * s) {
  symbol_p curr;
  symbol_p * prev;
  uint_t h = __string_hash(s) & (SYMBOLS_HASH_LENGTH - 1);
  DEBUG("symbol [%s] -> hash [%lu]", s, h);
  prev = &__symbols_hashtable[h];
  for(curr = *prev; curr; curr = *prev) {
    if (strcmp(s, curr->name) == 0) break;
    prev = &(curr->next);
  }
  return prev;
}

static symbol_p __symbol_alloc(symbol_p * dst, char * s, uint_t address) {
  symbol_p sym;
  uint_t len;
  DEBUG();
  if (dst == NULL || *dst != NULL || s == NULL || __symbols_free == NULL) return NULL;
  if ((len = strlen(s)) > SYMBOLS_NAME_LENGTH) {
    debug(DEBUG_ERR, "symbol name [%s] too long", s);
    return NULL;
  }
  sym = __symbols_free;
  __symbols_free = sym->next;
  sym->next = NULL;
  *dst = sym;
  strcpy(sym->name, s);
  sym->address = address;
  debug(DEBUG_INF, "[%s] added to hash as [%lx]", s, address);
  stats_symbols_free -= 1;
  stats_symbols_free_bytes -= symbol_s;
  stats_symbols_used += 1;
  stats_symbols_used_bytes += symbol_s;
  return sym;
}

uint_t splinter_get_symbol(char * s) {
  symbol_p * sym;
  uint_t address = 0;
  DEBUG("looking up [%s]", s);
  if (!s || !*s || __symbols_buffer == NULL) return address;
  sym = __symbol_find(s);
  if (*sym) {
    debug(DEBUG_INF, "[%s] found in hash", s);
    return (*sym)->address;
  }
  address = splinter_find_symbol(s);
  if (!address) {
    debug(DEBUG_ERR, "[%s] not found in hash", s);
    return address;
  }
  __symbol_alloc(sym, s, address);
  return address;
}

int symbols_init(uint_t n) {
  uint_t i;
  debug(DEBUG_INF, "size = %lu", n);
  if (!n) return symbols_cleanup();
  if (__symbols_buffer) return -1;
  __symbols_free = __symbols_buffer = splinter_memory_alloc(n * symbol_s);
  if (__symbols_buffer == NULL) {
    debug(DEBUG_ERR, "could not alloc symbols buffer");
    return -1;
  }
  for(i = 0; i < n - 1; i++) {
    __symbols_buffer[i].next = &__symbols_buffer[i + 1];
  }
  memset(__symbols_hashtable, 0, SYMBOLS_HASH_LENGTH * sizeof(symbol_p));
  stats_symbols_total = stats_symbols_free = n;
  stats_symbols_total_bytes = stats_symbols_free_bytes = n * symbol_s;
  stats_symbols_used = stats_symbols_used_bytes = 0;
  stats_symbols_hash_size = SYMBOLS_HASH_LENGTH;
  stats_symbols_hash_bytes = SYMBOLS_HASH_LENGTH * sizeof(symbol_p);
  debug(DEBUG_DBG, "symbols buffer = %p - %p", __symbols_buffer, ((byte_p)__symbols_buffer) + n * symbol_s);
  return 0;
}

int symbols_cleanup(void) {
  if (__symbols_buffer == NULL) return -1;
  DEBUG();
  __symbols_free = __symbols_buffer = splinter_memory_free(__symbols_buffer);
  memset(__symbols_hashtable, 0, SYMBOLS_HASH_LENGTH * sizeof(symbol_p));
  stats_symbols_total = stats_symbols_free = stats_symbols_used =
    stats_symbols_total_bytes = stats_symbols_free_bytes = stats_symbols_used_bytes = 0;
  stats_symbols_hash_size = stats_symbols_hash_bytes = 0;
  return 0;
}
