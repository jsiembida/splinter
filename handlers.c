
#include "splinter.h"

/*
 * Each 'packet' is preceded with a 'magic' sequence of bytes.
 * And if it is not, is discarded.
 */

#define PROTO_PING_REQ  "SPLINTER_PING_REQ"
#define PROTO_PING_ANS  "SPLINTER_PING_ANS"
#define PROTO_INFO_REQ  "SPLINTER_INFO_REQ"
#define PROTO_INFO_ANS  "SPLINTER_INFO_ANS"
#define PROTO_STAT_REQ  "SPLINTER_STAT_REQ"
#define PROTO_STAT_ANS  "SPLINTER_STAT_ANS"
#define PROTO_HOOK_REQ  "SPLINTER_HOOK_REQ"
#define PROTO_HOOK_ANS  "SPLINTER_HOOK_ANS"
#define PROTO_UNHO_REQ  "SPLINTER_UNHO_REQ"
#define PROTO_UNHO_ANS  "SPLINTER_UNHO_ANS"
#define PROTO_DUMP_REQ  "SPLINTER_DUMP_REQ"
#define PROTO_DUMP_ANS  "SPLINTER_DUMP_ANS"
#define PROTO_ENAB_REQ  "SPLINTER_ENAB_REQ"
#define PROTO_ENAB_ANS  "SPLINTER_ENAB_ANS"
#define PROTO_ZERO_REQ  "SPLINTER_ZERO_REQ"
#define PROTO_ZERO_ANS  "SPLINTER_ZERO_ANS"
#define PROTO_SHOT_REQ  "SPLINTER_SHOT_REQ"
#define PROTO_SHOT_ANS  "SPLINTER_SHOT_ANS"

static int netstring_read_string(char ** s, char ** src, int * src_len) {
  unsigned len;
  int n;
  if (s == NULL || src == NULL || src_len == NULL) return -1;
  if (*src == NULL || *src_len < 3) return -1;
  if (sscanf(*src, "%6u%n", &len, &n) < 1) return -1;
  *src += n;
  *src_len -= n;
  if (**src != ':') return -1;
  *src += 1;
  *src_len -= 1;
  if (len > *src_len - 1) return -1;
  *s = *src;
  *src += len;
  *src_len -= len;
  if (**src != ',') return -1;
  **src = '\0';
  *src += 1;
  *src_len -= 1;
  return 0;
}

static int netstring_read_int(int * i, char ** src, int * src_len) {
  char * tmp;
  int err = netstring_read_string(&tmp, src, src_len);
  if (err || i == NULL) return err;
  if (sscanf(tmp, "%i", i) < 1) return -1;
  return 0;
}

static int netstring_read_uint(uint_t * u, char ** src, int * src_len) {
  char * tmp;
  int err = netstring_read_string(&tmp, src, src_len);
  if (err || u == NULL) return err;
  if (sscanf(tmp, "%lu", u) < 1) return -1;
  return 0;
}

static int netstring_write_data(char * src, int src_len, char ** dst, int * dst_len) {
  int err;
  if (src == NULL || src_len < 0 || dst == NULL || dst_len == NULL) return -1;
  if (*dst == NULL || *dst_len < 3) return -1;
  if (src_len > *dst_len - 10) return -1;
  err = sprintf(*dst, "%u:", src_len);
  *dst += err;
  *dst_len -= err;
  if (src_len) memcpy(*dst, src, src_len);
  *dst += src_len;
  *dst_len -= src_len;
  **dst = ',';
  *dst += 1;
  *dst_len -= 1;
  return 0;
}

static int netstring_write_string(char * s, char ** dst, int * dst_len) {
  if (s == NULL) return -1;
  return netstring_write_data(s, strlen(s), dst, dst_len);
}

static int netstring_write_int(int i, char ** dst, int * dst_len) {
  char buf[64];
  sprintf(buf, "%i", i);
  return netstring_write_string(buf, dst, dst_len);
}

static int netstring_write_uint(uint_t u, char ** dst, int * dst_len) {
  char buf[64];
  sprintf(buf, "%lu", u);
  return netstring_write_string(buf, dst, dst_len);
}

static int netstring_write_hook(char * ans, hook_p h, char ** dst, int * dst_len) {
  int i;
  int err = 0;
  DEBUG();
  if (ans) {
   if ((err = netstring_write_string(ans, dst, dst_len)) != 0) return err;
  }
  if (h) {
    if ((err = netstring_write_uint((uint_t)h->id, dst, dst_len)) == 0
      && (err = netstring_write_uint((uint_t)h->enabled, dst, dst_len)) == 0
      && (err = netstring_write_uint((uint_t)h->refcount, dst, dst_len)) == 0
      && (err = netstring_write_uint(h->address, dst, dst_len)) == 0
      && (err = netstring_write_uint(h->hits, dst, dst_len)) == 0
      && (err = netstring_write_uint(h->dropped, dst, dst_len)) == 0
      && (err = netstring_write_string((char *)h->text, dst, dst_len)) == 0) {
      for(i = 0; i < HOOK_STORE; i++)
        if ((err = netstring_write_uint(h->store[i], dst, dst_len)) != 0) break;
    }
  } else {
    if ((err = netstring_write_uint(0, dst, dst_len)) == 0)
      err = netstring_write_string(splinter_error_get(), dst, dst_len);
  }
  return err;
}

static int __handler_ping(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err, i;
  DEBUG();

  if ((err = netstring_read_int(&i, src, src_len)) != 0) return err;
  if ((err = netstring_write_string(PROTO_PING_ANS, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_int(i, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_string(SPLINTER_VERSION, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(CONTEXT_BUFF, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(CONTEXT_ARGS, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(CONTEXT_VARS, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(HOOK_STORE, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_memory_used, dst, dst_len)) != 0) return err;

  if ((err = netstring_write_uint(stats_strings_total_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_strings_free_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_strings_used, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_strings_used_bytes, dst, dst_len)) != 0) return err;

  if ((err = netstring_write_uint(stats_atoms_total, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_atoms_total_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_atoms_free, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_atoms_free_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_atoms_used, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_atoms_used_bytes, dst, dst_len)) != 0) return err;

  // A workaround to enforce hooks GC run before gathering the stats
  hook_get(0);

  if ((err = netstring_write_uint(stats_hooks_total, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_total_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_free, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_free_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_used, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_used_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_limbo, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_hooks_limbo_bytes, dst, dst_len)) != 0) return err;

  if ((err = netstring_write_uint(stats_symbols_total, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_symbols_total_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_symbols_free, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_symbols_free_bytes, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_symbols_used, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(stats_symbols_used_bytes, dst, dst_len)) != 0) return err;

  if ((err = netstring_write_uint(ringbuf_size, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(ringbuf_length, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(ringbuf_head, dst, dst_len)) != 0) return err;
  if ((err = netstring_write_uint(ringbuf_dropped, dst, dst_len)) != 0) return err;

  return 0;
}

static int __handler_stat(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  uint_t n;
  hook_p h;
  DEBUG();
  if ((err = netstring_read_uint(&n, src, src_len)) != 0) return err;
  if ((h = hook_get(n)) == NULL)
    splinter_error_set("no such entry");
  return netstring_write_hook(PROTO_STAT_ANS, h, dst, dst_len);
}

static int __handler_enab(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  hook_p h = NULL;
  uint_t n;
  uint_t e;
  DEBUG();
  if ((err = netstring_read_uint(&n, src, src_len)) != 0) return err;
  if ((h = hook_get(n)) == NULL) {
    splinter_error_set("no such entry");
    return netstring_write_hook(PROTO_ENAB_ANS, NULL, dst, dst_len);
  }
  if ((err = netstring_read_uint(&e, src, src_len)) != 0) return err;
  if (hook_in_use(h)) {
    h->enabled = (e != 0);
  }
  return netstring_write_hook(PROTO_ENAB_ANS, h, dst, dst_len);
}

static int __handler_zero(char ** src, int * src_len, char ** dst, int * dst_len) {
  int i, err;
  hook_p h = NULL;
  uint_t n;
  DEBUG();
  if ((err = netstring_read_uint(&n, src, src_len)) != 0) return err;
  if ((h = hook_get(n)) == NULL) {
    splinter_error_set("no such entry");
    return netstring_write_hook(PROTO_ENAB_ANS, NULL, dst, dst_len);
  }
  if (hook_in_use(h)) {
    h->hits = 0;
    h->dropped = 0;
    for(i = 0; i < HOOK_STORE; h->store[i++] = 0);
  }
  return netstring_write_hook(PROTO_ZERO_ANS, h, dst, dst_len);
}

static int __handler_dump(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  static char buf[IO_BUFF / 4 * 3];
  uint_t len = sizeof(buf);
  uint_t dropped = 0;
  DEBUG();
  if ((err = netstring_write_string(PROTO_DUMP_ANS, dst, dst_len)) != 0) return err;
  ringbuf_read((byte_p)buf, &len, &dropped,
    ringbuf_data, &ringbuf_head, &ringbuf_length, &ringbuf_dropped, ringbuf_size);
  if ((err = netstring_write_uint(dropped, dst, dst_len)) != 0) return err;
  return netstring_write_data(buf, len, dst, dst_len);
}

static int __handler_unho(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  uint_t hook_number;
  DEBUG();

  if ((err = netstring_read_uint(&hook_number, src, src_len)) != 0) return err;
  DEBUG("hook_number = %lu", hook_number);
  if (hook_uninstall(hook_number)) {
    return netstring_write_hook(PROTO_UNHO_ANS, NULL, dst, dst_len);
  } else {
    return netstring_write_hook(PROTO_UNHO_ANS, hook_get(hook_number), dst, dst_len);
  }
}

static int __handler_hook(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  char * symbol_name;
  char * entry_hook;
  char * exit_hook;
  char * hook_text;
  char c = 0;
  uint_t symbol_addr;
  hook_p h = NULL;
  DEBUG();

  // Get symbol/address to install hook at
  if ((err = netstring_read_string(&symbol_name, src, src_len)) != 0) goto hook_err;

  //
  // Parse the passed address, if not a numeric value,
  // try to lookup the symbol.
  if (sscanf(symbol_name, "0x%lx%c", &symbol_addr, &c) != 1
     && sscanf(symbol_name, "%lx%c", &symbol_addr, &c) != 1
     && sscanf(symbol_name, "%lu%c", &symbol_addr, &c) != 1) {
    if ((symbol_addr = splinter_get_symbol(symbol_name)) == 0) {
      splinter_error_set("symbol [%s] unknown", symbol_name);
      goto hook_err;
    }
  }

  DEBUG("symbol_addr=%lx", symbol_addr);

  // Get entry/exit hook strings
  if ((err = netstring_read_string(&entry_hook, src, src_len)) != 0) goto hook_err;
  DEBUG("entry_hook = [%s]", entry_hook);
  if ((err = netstring_read_string(&exit_hook, src, src_len)) != 0) goto hook_err;
  DEBUG("exit_hook = [%s]", exit_hook);
  if (!*entry_hook) entry_hook = NULL;
  if (!*exit_hook) exit_hook = NULL;
  if ((err = netstring_read_string(&hook_text, src, src_len)) != 0) goto hook_err;
  DEBUG("hook_text = [%s]", hook_text);
  if (!*hook_text) hook_text = NULL;

  if ((h = hook_install(symbol_addr, entry_hook, exit_hook, hook_text, ringbuf_dump, splinter_test_mode)) == NULL) goto hook_err;
  return netstring_write_hook(PROTO_HOOK_ANS, h, dst, dst_len);

hook_err:
  return netstring_write_hook(PROTO_HOOK_ANS, NULL, dst, dst_len);
}

static int __handler_shot(char ** src, int * src_len, char ** dst, int * dst_len) {
  int err;
  atom_p chain = NULL;
  char * chain_string = NULL;
  context_t ctx;

  DEBUG();

  if ((err = netstring_write_string(PROTO_HOOK_ANS, dst, dst_len)) != 0) return err;

  if ((err = netstring_read_string(&chain_string, src, src_len)) != 0) {
    return netstring_write_string("no shot definition", dst, dst_len);
  }

  if ((chain = parse_expression("shot expression", chain_string)) == NULL) {
    return netstring_write_string(splinter_error_get(), dst, dst_len);
  }

  if (!splinter_test_mode) {
    memset(&ctx, 0, sizeof(ctx));
    atom_call(chain, &ctx);
    ringbuf_dump(&ctx);
  }

  atom_free(chain);
  return netstring_write_string("", dst, dst_len);
}

int splinter_handle_request(char * src, int src_len, char * dst, int dst_len) {
  int err;
  char * tmp;
  int (*handler)(char **, int *, char **, int *) = NULL;

  DEBUG();
  splinter_error_clear();

  if ((err = netstring_read_string(&tmp, &src, &src_len)) != 0) return err;

  if (!strcmp(tmp, PROTO_PING_REQ)) handler = __handler_ping;
  else if (!strcmp(tmp, PROTO_STAT_REQ)) handler = __handler_stat;
  else if (!strcmp(tmp, PROTO_DUMP_REQ)) handler = __handler_dump;
  else if (!strcmp(tmp, PROTO_HOOK_REQ)) handler = __handler_hook;
  else if (!strcmp(tmp, PROTO_UNHO_REQ)) handler = __handler_unho;
  else if (!strcmp(tmp, PROTO_ENAB_REQ)) handler = __handler_enab;
  else if (!strcmp(tmp, PROTO_ZERO_REQ)) handler = __handler_zero;
  else if (!strcmp(tmp, PROTO_SHOT_REQ)) handler = __handler_shot;

  if (handler) {
    tmp = dst;
    if ((err = handler(&src, &src_len, &dst, &dst_len)) != 0) return -1;
  }

  DEBUG("%d bytes of output", (int)(dst - tmp));
  return dst - tmp;
}

