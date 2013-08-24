
/******************************************/

#include "splinter.h"

/******************************************/


// This is work in progress.


uint_t stats_memory_used = 0;


void * splinter_memory_alloc(uint_t size) {
  void * ptr;
  if (!size) return NULL;
  if ((ptr = calloc(1, size)) != NULL) {
    stats_memory_used += 1;
  } else {
    debug(DEBUG_ALL, "could not alloc %lu bytes", size);
  }
  return ptr;
}


void * splinter_memory_free(void *p) {
  if (p) {
    free(p);
    stats_memory_used -= 1;
  }
  return NULL;
}


int splinter_debug_level = 99;
int splinter_test_mode = 0;

char * splinter_find_variable(char * name) {
  return getenv(name);
}

uint_t splinter_find_symbol(char * name) {
  if (!name) return 0;
  return 0;
}

static int i = 0;
static char in[64*1024];
static char out[64*1024];

static void out_char(int c) {
  out[i++] = (char)(c & 0xff);
}

int main(int argc, char ** argv) {
  int err, len = read(0, in, 64*1024);
  if (len < 1) return -1;
  in[len] = 0;
  if (strings_init(STRING_BUFF)
    || atoms_init(MAX_ATOMS)
    || symbols_init(MAX_SYMBOLS))
    exit(-1);
  splinter_stats_dump();
  err = validate_expression("test", in, out_char);
  if (err == 0) {
    out[i] = 0;
    fprintf(stderr, "---\n%s\n---\n", out);
    return 0;
  }
  return -1;
}

