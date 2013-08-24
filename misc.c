
/********************************************************************/

#include "splinter.h"

/********************************************************************/


static char __error[ERROR_BUFF];

char * splinter_error_get() {
    return __error;
}

int __splinter_error_set(const char * function, int line, char * error, ...) {
    va_list args;
    if (error) {
        va_start(args, error);
        vsnprintf(__error, sizeof(__error) - 1, error, args);
        va_end(args);
        __debug(DEBUG_ERR, function, line, "%s", __error);
    } else {
        __error[0] = 0;
    }
    return -1;
}

void splinter_error_clear() {
  __error[0] = 0;
}


void splinter_stats_dump(void) {
  debug(DEBUG_INF, "memory used = %lu", stats_memory_used);

  debug(DEBUG_INF, "strings used = %lu", stats_strings_used);
  debug(DEBUG_INF, "strings used bytes = %lu", stats_strings_used_bytes);
  debug(DEBUG_INF, "strings free bytes = %lu", stats_strings_free_bytes);
  debug(DEBUG_INF, "strings total bytes = %lu", stats_strings_total_bytes);

  debug(DEBUG_INF, "atoms used = %lu", stats_atoms_used);
  debug(DEBUG_INF, "atoms used bytes = %lu", stats_atoms_used_bytes);
  debug(DEBUG_INF, "atoms free = %lu", stats_atoms_free);
  debug(DEBUG_INF, "atoms free bytes = %lu", stats_atoms_free_bytes);
  debug(DEBUG_INF, "atoms total = %lu", stats_atoms_total);
  debug(DEBUG_INF, "atoms total bytes = %lu", stats_atoms_total_bytes);

  debug(DEBUG_INF, "hooks used = %lu", stats_hooks_used);
  debug(DEBUG_INF, "hooks used bytes = %lu", stats_hooks_used_bytes);
  debug(DEBUG_INF, "hooks free = %lu", stats_hooks_free);
  debug(DEBUG_INF, "hooks free bytes = %lu", stats_hooks_free_bytes);
  debug(DEBUG_INF, "hooks limbo = %lu", stats_hooks_limbo);
  debug(DEBUG_INF, "hooks limbo bytes = %lu", stats_hooks_limbo_bytes);
  debug(DEBUG_INF, "hooks total = %lu", stats_hooks_total);
  debug(DEBUG_INF, "hooks total bytes = %lu", stats_hooks_total_bytes);

  debug(DEBUG_INF, "symbols used = %lu", stats_symbols_used);
  debug(DEBUG_INF, "symbols used bytes = %lu", stats_symbols_used_bytes);
  debug(DEBUG_INF, "symbols free = %lu", stats_symbols_free);
  debug(DEBUG_INF, "symbols free bytes = %lu", stats_symbols_free_bytes);
  debug(DEBUG_INF, "symbols total = %lu", stats_symbols_total);
  debug(DEBUG_INF, "symbols total bytes = %lu", stats_symbols_total_bytes);

  debug(DEBUG_INF, "ringbuf size = %lu", ringbuf_size);
  debug(DEBUG_INF, "ringbuf length = %lu", ringbuf_length);
  debug(DEBUG_INF, "ringbuf head = %li", ringbuf_head);
  debug(DEBUG_INF, "ringbuf dropped = %li", ringbuf_dropped);
}

void __splinter_memory_dump(const char * function, int line, const char * msg, byte_p mem) {
#ifdef __amd64__
  __debug(DEBUG_DBG, function, line, "%s 0x%016lx:"
#else
  __debug(DEBUG_DBG, function, line, "%s 0x%08lx:"
#endif
        " 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x",
        msg, (uint_t)mem, mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6], mem[7]);
}

uint_t splinter_get_timestamp(void) {
   uint_t t;
   __asm__ __volatile__(
#ifdef __amd64__
       "push %%rdx\n"
       "rdtsc\n"
       "shl $32, %%rdx\n"
       "or %%rdx, %%rax\n"
       "pop %%rdx"
#else
       "push %%edx\n"
       "rdtsc\n"
       "shr $4, %%eax\n"
       "shl $28, %%edx\n"
       "or %%edx, %%eax\n"
       "pop %%edx"
#endif
       : "=a"(t));
   return t;
}

CONTEXTCALL context_call(atom_p * a, hook_p h, context_p c) {
  int_t err;
  DEBUG("hook = %p atom = %p context = %p", h, a, c);
  if (h->enabled && !(c->flags & CONTEXT_FLAG_QUIT)) {
    c->link = (uint_t)h;
    err = (int_t)atom_call(*a, c);
    if (err < 0) {
      c->flags |= CONTEXT_FLAG_QUIT;
      return (uint_t)err;
    }
  }
  return 0;
}

CONTEXTCALL context_close(hook_p h, context_p c)
{
  DEBUG("hook = %p context = %p", h, c);
  if (h->enabled) {
    h->hits++;
    if (h->dumper) {
      if (c->index > CONTEXT_BUFF)
        h->dropped += c->index - CONTEXT_BUFF;
      h->dumper(c);
    }
  }
  return 0;
}
