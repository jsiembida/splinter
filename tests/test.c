
/******************************************/

#include "splinter.h"

/******************************************/

#define run()   runit(argc, argv)

int splinter_debug_level = 99;
int splinter_test_mode = 0;
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

char * splinter_find_variable(char * name) {
  return NULL;
}

uint_t splinter_find_symbol(char * name) {
  return 0;
}

int funnn(char *s, int argc, char **argv, int a) {
  int i = 0;
  int j = 3;
  int ret = a ? j + a : i + a + a + a;
  fprintf(stderr, "funnn: s = [%s], argc = %d, argv = %u, a = %d, ret = %d\n", s, argc, (unsigned) argv, a, ret);
  return ret;
}

void runit(int argc, char **argv) {
  static int i = 0;
  fprintf(stderr, "runit: ret = %d\n", funnn("string", argc, argv, i++));
}

static void dump_ringbuffer() {
  byte_t buf_data[1025];
  uint_t buf_length;
  uint_t buf_dropped;

  do {
    buf_length = sizeof(buf_data) - 1;
    ringbuf_read(buf_data, &buf_length, &buf_dropped, ringbuf_data, &ringbuf_head, &ringbuf_length, &ringbuf_dropped, ringbuf_size);

    if(buf_length) {
      buf_data[buf_length] = 0;
      fprintf(stderr, "dropped = %lu\n[%s]\n", buf_dropped, buf_data);
    }
  }
  while(buf_length > 0);
}

int main(int argc, char **argv)
{
  int i;
  context_t ctx;

  char *entry_hook_line =
      "{exec {print-str ' entry:'} [var 0 0]"
      "\n  {while <is-le [var 0] 10>"
      "\n    {exec"
      "\n      {print-char 32}"
      "\n      {print-hex0 [reg [var 0]]}"
      "\n      {if <is-null [reg [var 0]]>"
      "\n        (break)"
      "\n      }"
      "\n      [var 0 (add [var 0] 1)]"
      "\n    }"
      "\n  }"
      "\n  (print-char 10)"
      "\n}";

  char *exit_hook_line =
      "{exec {print-str '  exit:'} [var 0 0]"
      "\n  {while <is-le [var 0] 10>"
      "\n    {exec {print-str ' '} (print-hex0 [reg [var 0]]) [var 0 (add [var 0] 1)]}"
      "\n  }"
      "\n  (print-char 10)"
      "\n}";

  hook_p h;

  if (strings_init(STRING_BUFF)
    || atoms_init(MAX_ATOMS)
    || symbols_init(MAX_SYMBOLS)
    || ringbuf_init(4096)
    || hooks_init(4, NULL, NULL)) return -1;

  if (argc > 1) entry_hook_line = argv[1];
  if (argc > 2) exit_hook_line = argv[2];

  h = hook_install((uint_t)funnn, entry_hook_line, exit_hook_line, NULL, ringbuf_dump, splinter_test_mode);
  if (!h) {
      fprintf(stderr, "%s", splinter_error_get());
      return -1;
  }
  h->enabled = 1;
  memset(&ctx, 0, sizeof(ctx));
  for(i = 0; i < 1; i++) {
      context_call(&h->entry_chain, h, &ctx);
      context_call(&h->exit_chain, h, &ctx);
      context_close(h, &ctx);
  }

  dump_ringbuffer();

  return 0;
}
