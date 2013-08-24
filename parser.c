
/******************************************/

#include "splinter.h"

/******************************************/

//
// Parsebuf is mostly to facilitate keeping the track of line/column
// of parsed text. In case of parsing error a friendly message with
// a context can be returned. The overhead is negligible since parsing
// is a one-time operation.
//

struct __parsebuf_t {
  char * n; // 'name' for the parsing
  char * s; // pointer to parsed string
  int i;    // index in buffer of the char to get
  int l;    // line counter, 1-based
  int c;    // column counter, 1-based
  int _c;   // old column counter, 1-based
};

typedef struct __parsebuf_t parsebuf_t;
typedef parsebuf_t * parsebuf_p;

static int __parsebuf_next(parsebuf_p pb) {
  int c = pb->s[pb->i++];

  if (c == 10) {
    pb->_c = pb->c;
    pb->c = 1;
    pb->l++;
  } else {
    pb->c++;
  }

  return c;
}

static int __parsebuf_peek(parsebuf_p pb) {
  return pb->s[pb->i];
}

static int __parsebuf_prev(parsebuf_p pb) {
  if (pb->i <= 0) return -1;
  if (pb->s[--pb->i] == 10) {
    pb->c = pb->_c;
    pb->l--;
  } else {
    pb->c--;
  }
  return 0;
}

static int __parsebuf_snapshot(parsebuf_p cur, parsebuf_p old) {
  memcpy(old, cur, sizeof(*cur));
  return 0;
}

//
// Helper functions for parsers
//

#define is_symbolchar(c) (('a' <= (c) && (c) <= 'z') \
                       || ('A' <= (c) && (c) <= 'Z') \
                       || ('0' <= (c) && (c) <= '9') \
                       || (c)=='-' || (c)=='_'       \
                       || (c)=='$' || (c)=='@')

#define is_hexchar(c) (('a' <= (c) && (c) <= 'f') \
                    || ('A' <= (c) && (c) <= 'F') \
                    || ('0' <= (c) && (c) <= '9'))

#define is_whitespace(c) ((c)==' ' \
                       || (c)=='\t' \
                       || (c)=='\n' \
                       || (c)=='\r')

static int __consume_whitespace(parsebuf_p pb) {
  int c;
  do {
      c = __parsebuf_next(pb);
  } while(is_whitespace(c));
  return __parsebuf_prev(pb);
}

static int __strings_distance(char *s1, char *stop, char *s2) {
  char c1, c2;
  int i, distance = -1;

  if(s1 && s2) {
    for(i = 0;; s1++, s2++, i++) {
      c1 = *s1;
      c2 = *s2;
      if((!c1 || s1 == stop) && !c2) {
        distance = i ? 0 : -1;  // Perfect match
        break;
      }
      if((!c1 || s1 == stop) || !c2) {
        distance = i ? i : -1;  // Partial match
        break;
      }
      if('A' <= c1 && c1 <= 'Z')
        c1 += 'a' - 'A';
      if('A' <= c2 && c2 <= 'Z')
        c2 += 'a' - 'A';
      if(c1 != c2) {
        distance = i ? i : -1;  // Partial match
        break;
      }
    }
  }
  return distance;
}

static int __parse_hex_chunk(int c) {
  if ('a' <= c && c <= 'f') return 10 + (c - 'a');
  if ('A' <= c && c <= 'F') return 10 + (c - 'A');
  if ('0' <= c && c <= '9') return c - '0';
  return -1;
}

static int __parse_hex_char(parsebuf_p pb) {
  int c1, c2;
  if ((c1 = __parsebuf_next(pb)) <= 0) return -1;
  if ((c1 = __parse_hex_chunk(c1)) < 0) return -1;
  if ((c2 = __parsebuf_next(pb)) <= 0) return -1;
  if ((c2 = __parse_hex_chunk(c2)) < 0) return -1;
  return (c1 << 4) | c2;
}

static int __parse_quote_char(parsebuf_p pb) {
  int c;
  DEBUG();
  if ((c = __parsebuf_next(pb)) <= 0) return -1;
  switch(c) {
    case 'n': return 10;
    case 'r': return 13;
    case 't': return 9;
    case 'b': return 8;
    case 'x': return __parse_hex_char(pb);
    default: return c;
  }
}

/******************************************/

static int parse_literal(parsebuf_p pb, char **start, char **stop, int terminator)
{
  int c;
  DEBUG();

  *start = pb->s + pb->i;
  for(; (c = __parsebuf_next(pb)) > 0 && is_symbolchar(c) && (c != terminator););
  if (c <= 0) return -1;
  __parsebuf_prev(pb);
  *stop = pb->s + pb->i;
  if (*start >= *stop) return -1;
  if (!is_whitespace(c) && c != terminator) return -1;

  return 0;
}

static atom_p parse_string(parsebuf_p pb, char terminator, int print_mode)
{
  int c, err;
  atom_p a = NULL;
  DEBUG();

  if ((a = atom_alloc_string(print_mode ? operator_string : operator_value, NULL, NULL)) == NULL)
    return NULL;

  while((c = __parsebuf_next(pb)) > 0) {
    if (c == terminator) {
      DEBUG("parsed string atom [%s]", (char *)atom_data(a));
      return a;
    } else if (c == '\\') {
      if ((err = __parse_quote_char(pb)) <= 0) break;
      if (string_append((byte_p *)(&atom_data(a)), err & 0xff)) break;
    } else if (c == '%') {
      if ((err = __parse_hex_char(pb)) <= 0) break;
      if (string_append((byte_p *)(&atom_data(a)), err & 0xff)) break;
    } else {
      if (string_append((byte_p *)(&atom_data(a)), c)) break;
    }
  }
  return atom_free(a);
}

static atom_p parse_symbol(parsebuf_p pb, char terminator, int print_mode)
{
  char * symbol_start;
  char * symbol_stop;
  int symbol_length;
  uint_t symbol_address;
  static char symbol_buffer[128];
  DEBUG();

  if (parse_literal(pb, &symbol_start, &symbol_stop, terminator))
    return NULL;
  if (symbol_start[0] != '@' ||
      !(('a' <= symbol_start[1] && symbol_start[1] <= 'z')
      || ('A' <= symbol_start[1] && symbol_start[1] <= 'Z')
      || ('0' <= symbol_start[1] && symbol_start[1] <= '9')
      || symbol_start[1] == '_')) return NULL;
  symbol_length = symbol_stop - (++symbol_start);
  if (symbol_length > sizeof(symbol_buffer) - 1)
    return NULL;
  strncpy(symbol_buffer, symbol_start, symbol_length);
  symbol_buffer[symbol_length] = '\0';
  symbol_address = splinter_get_symbol(symbol_buffer);
  if (!symbol_address)
    return NULL;
  DEBUG("parsed symbol atom [%s] -> [%lx]", symbol_buffer, symbol_address);
  return atom_alloc_plain(print_mode ? operator_hex : operator_value, symbol_address);
}

static atom_p parse_variable(parsebuf_p pb, char terminator, int print_mode)
{
  char * var_start;
  char * var_stop;
  char * var_value;
  int var_length;
  static char var_buffer[128];
  DEBUG();

  if (parse_literal(pb, &var_start, &var_stop, terminator))
    return NULL;
  if (var_start[0] != '$' ||
      !(('a' <= var_start[1] && var_start[1] <= 'z')
      || ('A' <= var_start[1] && var_start[1] <= 'Z')
      || ('0' <= var_start[1] && var_start[1] <= '9')
      || var_start[1] == '_')) return NULL;
  var_length = var_stop - (++var_start);
  if (var_length > sizeof(var_buffer) - 1)
    return NULL;
  strncpy(var_buffer, var_start, var_length);
  var_buffer[var_length] = '\0';
  var_value = splinter_find_variable(var_buffer);
  if (!var_value)
    return NULL;
  var_length = strlen(var_value);
  DEBUG("parsed variable atom [%s] -> [%s]", var_buffer, var_value);
  return atom_alloc_string(print_mode ? operator_string : operator_value, var_value, var_value + var_length);
}

static atom_p parse_oct(parsebuf_p pb, int print_mode)
{
  uint_t n, o;
  atom_p a = NULL;
  int c, valid = 1;
  DEBUG();

  for(n = o = 0; '0' <= (c = __parsebuf_next(pb)) && c <= '7';) {
    if(valid) {
      n = n * 8 + (c - '0');
      if(n < o)
        valid = 0;
      else
        o = n;
    }
  }

  __parsebuf_prev(pb);

  if(valid) {
    DEBUG("parsed octal number [%lu]", n);
    a = atom_alloc_plain(print_mode ? operator_uint : operator_value, n);
  }

  return a;
}

static atom_p parse_int(parsebuf_p pb, int print_mode)
{
  int_t n, o;
  atom_p a = NULL;
  int c, valid = 1;
  DEBUG();

  if((c = __parsebuf_next(pb)) != '-') return a;

  for(n = o = 0; '0' <= (c = __parsebuf_next(pb)) && c <= '9';) {
    if(valid) {
      n = n * 10 + (c - '0');
      if(n < o)
        valid = 0;
      else
        o = n;
    }
  }

  __parsebuf_prev(pb);

  if(valid) {
    DEBUG("parsed int number [%li]", -n);
    a = atom_alloc_plain(print_mode ? operator_int : operator_value, (uint_t) (-n));
  }

  return a;
}

static atom_p parse_uint(parsebuf_p pb, int print_mode)
{
  uint_t n, o;
  atom_p a = NULL;
  int c, valid = 1;
  DEBUG();

  for(n = o = 0; '0' <= (c = __parsebuf_next(pb)) && c <= '9';) {
    if(valid) {
      n = n * 10 + (c - '0');
      if(n < o)
        valid = 0;
      else
        o = n;
    }
  }

  __parsebuf_prev(pb);

  if(valid) {
    DEBUG("parsed uint number [%lu]", n);
    a = atom_alloc_plain(print_mode ? operator_uint : operator_value, n);
  }

  return a;
}

static atom_p parse_hex(parsebuf_p pb, int print_mode)
{
  uint_t n, o, i;
  atom_p a = NULL;
  int c, valid = 1;
  DEBUG();

  if (__parsebuf_next(pb) != '0') return NULL;
  if ((c = __parsebuf_next(pb)) != 'x'
          && c != 'X') return NULL;

  for(n = o = 0;;) {
    c = __parsebuf_next(pb);
    if('0' <= c && c <= '9') {
      i = c - '0';
    } else if('a' <= c && c <= 'f') {
      i = c - 'a' + 10;
    } else if('A' <= c && c <= 'F') {
      i = c - 'A' + 10;
    } else {
      break;
    }
    if(valid) {
      n = (n << 4) + i;
      if(n < o)
        valid = 0;
      else
        o = n;
    }
  }

  __parsebuf_prev(pb);

  if(valid) {
    DEBUG("parsed hex number [%lx]", n);
    a = atom_alloc_plain(print_mode ? operator_hex : operator_value, n);
  }

  return a;
}

struct __operator
{
  char *token;
  atom_data_callback_t exec_call;
  int mode;
} operators[] =
{
  //
  // WARNING!!!
  //
  // The order of the below definitions matters!
  // As the parser picks the first of equally matching
  // strings it can lead to unwanted results.
  //
  // Example:
  // "char" and "call" as starting with c letter colide,
  // that is, "(c 10)" means "print LF" if "char" is declared
  // first. But if "call" is first it will be interpreted as
  // "call function @ address 10" which is not necesarily what
  // we want.
  //

  { "exec",          operator_exec,          0},
  { "print",         operator_exec,          1},

  { "memory",        operator_memory,        0},
  { "register",      operator_register,      0},
  { "argument",      operator_argument,      0},
  { "variable",      operator_variable,      0},
  { "store",         operator_store,         0},
  { "return",        operator_return,        0},

  { "print-string",  operator_print_string,  0},
  { "print-char",    operator_print_char,    0},
  { "print-byte",    operator_print_byte,    0},
  { "print-int",     operator_print_int,     0},
  { "print-uint",    operator_print_uint,    0},
  { "print-hex",     operator_print_hex,     0},
  { "print-hex0",    operator_print_hex0,    0},
  { "print-chars",   operator_print_chars,   0},
  { "print-bytes",   operator_print_bytes,   0},
  { "print-uints",   operator_print_uints,   0},
  { "print-argv",    operator_print_argv,    0},
  { "print-ipv4",    operator_print_ipv4,    0},

  { "buff-flush",    operator_buffer_flush,  0},
  { "buff-clear",    operator_buffer_clear,  0},

  { "add",           operator_add,           0},
  { "sub",           operator_sub,           0},
  { "mul",           operator_mul,           0},
  { "div",           operator_div,           0},

  { "and",           operator_and,           0},
  { "or",            operator_or,            0},
  { "not",           operator_not,           0},

  { "bit-shl",       operator_bit_shl,       0},
  { "bit-shr",       operator_bit_shr,       0},
  { "bit-and",       operator_bit_and,       0},
  { "bit-or",        operator_bit_or,        0},
  { "bit-xor",       operator_bit_xor,       0},
  { "bit-not",       operator_bit_not,       0},

  { "if",            operator_if,            0},
  { "not-if",        operator_not_if,        0},
  { "is-eq",         operator_is_eq,         0},
  { "is-lt",         operator_is_lt,         0},
  { "is-le",         operator_is_le,         0},
  { "is-gt",         operator_is_gt,         0},
  { "is-ge",         operator_is_ge,         0},
  { "is-null",       operator_is_null,       0},
  { "is-error",      operator_is_err,        0},

  { "str-equal",     operator_str_equal,     0},
  { "str-length",    operator_str_length,    0},
  { "str-starts",    operator_str_starts,    0},
  { "str-ends",      operator_str_ends,      0},
  { "str-find",      operator_str_find,      0},
  { "str-contains",  operator_str_contains,  0},

  { "flip",          operator_flip,          0},
  { "repeat",        operator_repeat,        0},
  { "while",         operator_while,         0},
  { "not-while",     operator_not_while,     0},
  { "break",         operator_break,         0},
  { "quit",          operator_quit,          0},

  { "call",          operator_call,          0},

// #ifdef __KERNEL__
  { "pid",           operator_pid,           0},
  { "uid",           operator_uid,           0},
  { "task",          operator_task,          0},
  { "time",          operator_time,          0},
  { "signature",     operator_signature,     0},
  { "current",       operator_current,       0},
  { "is-pid",        operator_is_pid,        0},
// #endif

  { "timestamp",     operator_timestamp,     0},

  { NULL, NULL, 0} // Terminating NULLs
};

static struct __operator * __find_closest_token(parsebuf_p pb, char terminator)
{
  char * start, * stop;
  struct __operator *closest_operator = NULL;
  struct __operator *current_operator = operators;
  int closest_distance = -1, current_distance;
  parsebuf_t buf;
  DEBUG();

  __parsebuf_snapshot(pb, &buf);

  if(parse_literal(pb, &start, &stop, terminator))
    return NULL;

  for(; current_operator->token; current_operator++)
  {
    if((current_distance = __strings_distance(start, stop, current_operator->token)) == 0) {
      // A perfect match, return it
      DEBUG("found perfect match for [%s]", current_operator->token);
      closest_distance = current_distance;
      closest_operator = current_operator;
      break;
    }
    if(current_distance > 0) {
      if(closest_distance < 0 || current_distance > closest_distance) {
        closest_distance = current_distance;
        closest_operator = current_operator;
      }
    }
  }

  if (closest_distance > 0 && closest_distance < 3) {
    splinter_error_return(NULL, "%s ambiguous keyword @ %d:%d - %d:%d", buf.n, buf.l, buf.c, pb->l, pb->c);
  }

  if(closest_operator) {
    DEBUG("parsed keyword [%s] distance = %d", closest_operator->token, closest_distance);
    return closest_operator;
  }

  splinter_error_return(NULL, "%s invalid keyword @ %d:%d - %d:%d", buf.n, buf.l, buf.c, pb->l, pb->c);
  return NULL;
}

static void __parse_out_char(expression_callback_t out, char c) {
  if (out == NULL) return;
  out(c);
}

static void __parse_out_string(expression_callback_t out, char * s, int len) {
  if (out == NULL) return;
  while(len-- > 0) out(*s++);
}

static void __parse_out_indentation(expression_callback_t out, int len) {
  if (out == NULL) return;
  while(len-- > 0) out(' ');
}

static void __parse_out_line(expression_callback_t out, char * s, int len, int indentation) {
  __parse_out_indentation(out, indentation);
  __parse_out_string(out, s, len);
}

static atom_p parse_list(parsebuf_p pb, expression_callback_t out, int indentation)
{
  int c, i, terminator;
  atom_p first, prev, curr;
  struct __operator * operator;
  parsebuf_t buf;
  DEBUG();

  // Grab the opening parenthesis, or whatever it is
  __consume_whitespace(pb);
  __parsebuf_snapshot(pb, &buf);
  if((c = __parsebuf_next(pb)) == '(') {
    terminator = ')';
  } else if(c == '[') {
    terminator = ']';
  } else if(c == '<') {
    terminator = '>';
  } else if(c == '{') {
    terminator = '}';
  } else {
    splinter_error_return(NULL, "%s invalid list opening @ %d:%d", buf.n, buf.l, buf.c);
  }

  __consume_whitespace(pb);
  if ((operator = __find_closest_token(pb, terminator)) == NULL)
    return NULL;

  __parse_out_indentation(out, indentation);
  __parse_out_char(out, c);
  __parse_out_string(out, operator->token, (int)strlen(operator->token));

  for(first = prev = curr = NULL; 1;) {
    __consume_whitespace(pb);
    i = pb->i;
    __parse_out_char(out, '\n');
    if((c = __parsebuf_next(pb)) <= 0) {
      splinter_error_set("%s missing list closing @ %d:%d", buf.n, pb->l, pb->c);
      return atom_free(first);
    } else if(c == terminator) {
      if ((curr = atom_alloc_list(operator->exec_call, first)) == NULL) {
        return atom_free(first);
      }
      __parse_out_indentation(out, indentation);
      __parse_out_char(out, terminator);
      return curr;
    } else if(c == '0' && (__parsebuf_peek(pb) == 'x' || __parsebuf_peek(pb) == 'X')) {
      __parsebuf_prev(pb);
      curr = parse_hex(pb, operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else if('0' <= c && c <= '9') {
      __parsebuf_prev(pb);
      curr = (c == '0') ? parse_oct(pb, operator->mode) : parse_uint(pb, operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else if(c == '-' && ('0' <= __parsebuf_peek(pb) && __parsebuf_peek(pb) <= '9')) {
      __parsebuf_prev(pb);
      curr = parse_int(pb, operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else if(c == '(' || c == '[' || c == '<' || c == '{') {
      __parsebuf_prev(pb);
      curr = parse_list(pb, out, indentation + 2);
    } else if(c == '\'') {
      curr = parse_string(pb, '\'', operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else if(c == '"') {
      curr = parse_string(pb, '"', operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else if (c == '$') {
      __parsebuf_prev(pb);
      curr = parse_variable(pb, terminator, operator->mode);
      if (curr != NULL) __parse_out_line(out, (char *)curr->data, strlen((char *)curr->data), indentation + 2);
    } else if (c == '@') {
      __parsebuf_prev(pb);
      curr = parse_symbol(pb, terminator, operator->mode);
      if (curr != NULL) __parse_out_line(out, pb->s + i, pb->i - i, indentation + 2);
    } else {
      curr = NULL;
    }

    if(curr == NULL) {
      return atom_free(first);
    }

    if(first == NULL) {
      first = prev = curr;
    } else {
      prev->next = curr;
      prev = curr;
    }
  }
}

atom_p parse_expression(char * n, char * s) {
  parsebuf_t pb;
  DEBUG();
  pb.n = n;
  pb.s = s;
  pb.i = 0;
  pb.l = 1;
  pb.c = 1;
  pb._c = -1;
  return parse_list(&pb, NULL, 0);
}

int validate_expression(char * n, char * s, expression_callback_t out) {
  parsebuf_t pb;
  atom_p a;
  DEBUG();
  pb.n = n;
  pb.s = s;
  pb.i = 0;
  pb.l = 1;
  pb.c = 1;
  pb._c = -1;
  a = parse_list(&pb, out, 0);
  if (a != NULL) {
    atom_free(a);
    return 0;
  }
  return -1;
}
