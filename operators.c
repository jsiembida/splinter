
/******************************************/

#include "splinter.h"

/******************************************/

//
// __print_char is a hot spot as pretty much majority
// of the routines end up calling it. Compiler inlines
// it, but it is not enough, probably handwritten
// assembly preprocessor macro could do better?
//

#ifdef SPLINTER_TRUNCATE
static CONTEXTCALL __print_char(int c, context_p o) {
   if (o->index < CONTEXT_BUFF) {
      o->buffer[o->index++] = c;
   }
   return 0;
}
#else
static CONTEXTCALL __print_char(int c, context_p o) {
   o->buffer[(o->index++) & (CONTEXT_BUFF - 1)] = c;
   return 0;
}
#endif

static CONTEXTCALL __print_string(char * c, context_p o)
{
   if(c) {
      for(; *c; c++)
         __print_char(*c, o);
   } else {
      debug(DEBUG_ERR, "NULL pointer");
      __print_char('N', o);
      __print_char('U', o);
      __print_char('L', o);
      __print_char('L', o);
   }
   return 0;
}

static char * __hex_lookup_table = "0123456789abcdef";

static CONTEXTCALL __print_byte(uint_t hex, context_p o)
{
   __print_char(__hex_lookup_table[(hex >> 4) & 0x0f], o);
   __print_char(__hex_lookup_table[(hex >> 0) & 0x0f], o);
   return 0;
}

static CONTEXTCALL __print_hex0(uint_t hex, context_p o)
{
   int i;
   DEBUG();
   for(i = (uint_s * 8) - 4; i >= 0; i -= 4)
      __print_char(__hex_lookup_table[(hex >> i) & 0x0f], o);
   return 0;
}

static CONTEXTCALL __print_hex(uint_t hex, context_p o)
{
   char buff[32];
   int i;

   if(!hex)
      return __print_char('0', o);

   for(i = sizeof(buff) - 1; hex; hex >>= 4)
      buff[i--] = __hex_lookup_table[hex & 0x0f];
   for(i++; i < sizeof(buff); i++)
      __print_char(buff[i], o);

   return 0;
}

// Needs optimization, that is, an optimized
// implementation needs to be stolen.
static CONTEXTCALL __print_uint(uint_t u, context_p o, int_t width)
{
   char buff[32];
   uint_t j = sizeof(buff) - 1, l = 0;

   if(u) {
      for(; u; u /= 10, l++)
         buff[j--] = '0' + (u % 10);
   } else {
      buff[j--] = '0';
      l++;
   }

   if(0 < width && width < sizeof(buff)) {
      for(; l < width; l++)
         buff[j--] = '0';
   }

   for(j++; j < sizeof(buff);)
      __print_char(buff[j++], o);

   return 0;
}

static CONTEXTCALL __print_int(int_t i, context_p o, int_t width)
{
   if(i < 0) {
      return __print_char('-', o) + __print_uint(-i, o, width);
   } else {
      return __print_uint(i, o, width);
   }
}

/***********************************************************/

CONTEXTCALL operator_null(atom_p a, context_p c)
{
   DEBUG();
   return 0;
}

CONTEXTCALL operator_value(atom_p a, context_p c)
{
   DEBUG();
   return atom_data(a);
}

CONTEXTCALL operator_string(atom_p a, context_p c)
{
   DEBUG();
   return __print_string((char *)atom_data(a), c);
}

CONTEXTCALL operator_hex(atom_p a, context_p c)
{
   DEBUG();
   return __print_hex(atom_data(a), c);
}

CONTEXTCALL operator_int(atom_p a, context_p c)
{
   DEBUG();
   return __print_int(atom_data(a), c, -1);
}

CONTEXTCALL operator_uint(atom_p a, context_p c)
{
   DEBUG();
   return __print_uint(atom_data(a), c, -1);
}

CONTEXTCALL operator_exec(atom_p a, context_p c)
{
   uint_t i = 0;
   DEBUG();
   for(a = atom_child(a); a; a = atom_next(a))
      if ((i = atom_call(a, c)) != 0) break;
   return i;
}

/***********************************************************/

CONTEXTCALL operator_add(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   for(a = atom_child(a); a; a = atom_next(a))
      k += atom_call(a, c);
   return k;
}

CONTEXTCALL operator_sub(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a))
         k -= atom_call(a, c);
   }
   return k;
}

CONTEXTCALL operator_mul(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a))
         k *= atom_call(a, c);
   }
   return k;
}

CONTEXTCALL operator_div(atom_p a, context_p c)
{
   uint_t k = 0, i;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a)) {
         i = atom_call(a, c);
         k = i ? k / i : k;
      }
   }
   return k;
}

/***********************************************************/

CONTEXTCALL operator_and(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = (atom_call(a, c) != 0);
      for(a = atom_next(a); a; a = atom_next(a))
         k &= (atom_call(a, c) != 0);
   }
   return k;
}

CONTEXTCALL operator_or(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = (atom_call(a, c) != 0);
      for(a = atom_next(a); a; a = atom_next(a))
         k |= (atom_call(a, c) != 0);
   }
   return k;
}

CONTEXTCALL operator_not(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      return atom_call(a, c) ? 0 : 1;
   return 0;
}

/***********************************************************/

CONTEXTCALL operator_bit_and(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a))
         k &= atom_call(a, c);
   }
   return k;
}

CONTEXTCALL operator_bit_or(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a))
         k |= atom_call(a, c);
   }
   return k;
}

CONTEXTCALL operator_bit_xor(atom_p a, context_p c)
{
   uint_t k = 0;
   DEBUG();
   if((a = atom_child(a)) != 0) {
      k = atom_call(a, c);
      for(a = atom_next(a); a; a = atom_next(a))
         k ^= atom_call(a, c);
   }
   return k;
}

CONTEXTCALL operator_bit_not(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      return ~atom_call(a, c);
   return 0;
}

CONTEXTCALL operator_bit_shr(atom_p a, context_p c)
{
   uint_t v = 0;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      v = atom_call(a, c);
      if(v && (a = atom_next(a)) != NULL)
         v >>= atom_call(a, c);
   }
   return v;
}

CONTEXTCALL operator_bit_shl(atom_p a, context_p c)
{
   uint_t v = 0;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      v = atom_call(a, c);
      if(v && (a = atom_next(a)) != NULL)
         v <<= atom_call(a, c);
   }
   return v;
}

/***********************************************************/

CONTEXTCALL operator_return(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) == NULL)
      return c->ret;
   c->ret = atom_call(a, c);
   return 0;
}

CONTEXTCALL operator_memory(atom_p a, context_p c)
{
   uint_t mem;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      mem = atom_call(a, c);
      if(!mem)
         return 0;
      if((a = atom_next(a)) == NULL)
         return *((uint_t *) mem);
      *((uint_t *) mem) = atom_call(a, c);
   }
   return 0;
}

CONTEXTCALL operator_register(atom_p a, context_p c)
{
   uint_t reg;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      reg = atom_call(a, c);
      if(reg >= CONTEXT_REGS)
         return 0;
      if((a = atom_next(a)) == NULL)
         return (&(c->reg0))[reg];
      (&(c->reg0))[reg] = atom_call(a, c);
   }
   return 0;
}

CONTEXTCALL operator_argument(atom_p a, context_p c)
{
   uint_t arg;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      arg = atom_call(a, c);
      if(arg >= CONTEXT_ARGS)
         return 0;
      if((a = atom_next(a)) == NULL)
         return (&(c->arg0))[arg];
      (&(c->arg0))[arg] = atom_call(a, c);
   }
   return 0;
}

CONTEXTCALL operator_variable(atom_p a, context_p c)
{
   uint_t var;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      var = atom_call(a, c);
      if(var >= CONTEXT_VARS)
         return 0;
      if((a = atom_next(a)) == NULL)
         return (&(c->var0))[var];
      (&(c->var0))[var] = atom_call(a, c);
   }
   return 0;
}

CONTEXTCALL operator_store(atom_p a, context_p c)
{
   uint_t store;
   hook_p h;
   DEBUG();
   if((h = (hook_p)c->link) != NULL && (a = atom_child(a)) != NULL) {
      store = atom_call(a, c);
      if(store >= HOOK_STORE)
         return 0;
      if((a = atom_next(a)) == NULL)
         return h->store[store];
      h->store[store] = atom_call(a, c);
   }
   return 0;
}

/***********************************************************/

CONTEXTCALL operator_buffer_flush(atom_p a, context_p c)
{
   hook_p h;
   DEBUG();
   if((h = (hook_p)c->link) != NULL && h->dumper) {
      if(c->index > CONTEXT_BUFF)
         h->dropped += c->index - CONTEXT_BUFF;
      h->dumper(c);
   }
   return 0;
}

CONTEXTCALL operator_buffer_clear(atom_p a, context_p c)
{
   DEBUG();
   c->index = 0;
   return 0;
}

/***********************************************************/

CONTEXTCALL operator_print_char(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      __print_char(atom_call(a, c) & 0xff, c);
   return 0;
}

CONTEXTCALL operator_print_byte(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      __print_byte(atom_call(a, c) & 0xff, c);
   return 0;
}

CONTEXTCALL operator_print_hex(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      __print_hex(atom_call(a, c), c);
   return 0;
}

CONTEXTCALL operator_print_hex0(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL)
      __print_hex0(atom_call(a, c), c);
   return 0;
}

CONTEXTCALL operator_print_int(atom_p a, context_p c)
{
   uint_t i;
   int_t l;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      i = atom_call(a, c);
      if ((a = atom_next(a)) != NULL) {
         l = (int_t)atom_call(a, c);
      } else {
         l = -1;
      }
      __print_int(i, c, l);
   }
   return 0;
}

CONTEXTCALL operator_print_uint(atom_p a, context_p c)
{
   uint_t u;
   int_t l;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      u = atom_call(a, c);
      if ((a = atom_next(a)) != NULL) {
         l = (int_t)atom_call(a, c);
      } else {
         l = -1;
      }
      __print_uint(u, c, l);
   }
   return 0;
}

CONTEXTCALL operator_print_chars(atom_p a, context_p c)
{
   uint_t l, i;
   byte_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      b = (byte_p) atom_call(a, c);
      if(!b || (a = atom_next(a)) == NULL)
         return 0;
      l = atom_call(a, c);
      a = atom_next(a);
      for(i = 0; i < l; i++, b++) {
         __print_char((uint_t) (*b), c);
         if(i < l - 1) {
            if (a) {
               operator_string(a, c);
            } else {
               __print_string(" ", c);
            }
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_print_bytes(atom_p a, context_p c)
{
   uint_t l, i;
   byte_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      b = (byte_p) atom_call(a, c);
      if(!b || (a = atom_next(a)) == NULL)
         return 0;
      l = atom_call(a, c);
      a = atom_next(a);
      for(i = 0; i < l; i++, b++) {
         __print_byte((uint_t) (*b), c);
         if(i < l - 1) {
            if (a) {
               operator_string(a, c);
            } else {
               __print_string(" ", c);
            }
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_print_uints(atom_p a, context_p c)
{
   uint_t l, i;
   uint_p v;

   DEBUG();
   if((a = atom_child(a)) != NULL) {
      v = (uint_p) atom_call(a, c);
      if(!v || (a = atom_next(a)) == NULL)
         return 0;
      l = atom_call(a, c);
      a = atom_next(a);
      for(i = 0; i < l; i++, v++) {
         __print_hex0(*v, c);
         if(i < l - 1) {
            if (a) {
               operator_string(a, c);
            } else {
               __print_string(" ", c);
            }
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_print_string(atom_p a, context_p c)
{
   DEBUG();
   for(a = atom_child(a); a; a = atom_next(a))
      __print_string((char *)atom_call(a, c), c);
   return 0;
}

CONTEXTCALL operator_print_argv(atom_p a, context_p c)
{
   int_t limit = -1, i;
   char **val;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      val = (char **) atom_call(a, c);
      if ((a = atom_next(a)) != NULL) {
         limit = (int_t)atom_call(a, c);
         a = atom_next(a);
      }
      if (limit >= 0) {
         for(i = 0; i < limit && *val; i++, val++) {
            __print_string(*val, c);
            if(i < limit - 1) {
               if (a) {
                  operator_string(a, c);
               } else {
                  __print_string(", ", c);
               }
            }
         }
      } else {
         while(*val) {
            __print_string(*val, c);
            val++;
            if(*val) {
               if (a) {
                  operator_string(a, c);
               } else {
                  __print_string(", ", c);
               }
            }
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_print_return(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) == NULL)
      __print_hex0(c->ret, c);
   return 0;
}

CONTEXTCALL operator_print_memory(atom_p a, context_p c)
{
   uint_t mem;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      if ((mem = atom_call(a, c)) != 0)
         __print_hex0(*((uint_t *)mem), c);
   }
   return 0;
}

CONTEXTCALL operator_print_register(atom_p a, context_p c)
{
   uint_t reg;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      if ((reg = atom_call(a, c)) < CONTEXT_REGS)
         __print_hex0((&(c->reg0))[reg], c);
   }
   return 0;
}

CONTEXTCALL operator_print_argument(atom_p a, context_p c)
{
   uint_t arg;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      arg = atom_call(a, c);
      if (arg < CONTEXT_ARGS)
         __print_hex0((&(c->arg0))[arg], c);
   }
   return 0;
}

CONTEXTCALL operator_print_variable(atom_p a, context_p c)
{
   uint_t var;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      if ((var = atom_call(a, c)) < CONTEXT_VARS)
         __print_hex0((&(c->var0))[var], c);
   }
   return 0;
}

CONTEXTCALL operator_print_store(atom_p a, context_p c)
{
   uint_t store;
   hook_p h;
   DEBUG();
   if((h = (hook_p)c->link) != NULL && (a = atom_child(a)) != NULL) {
      if ((store = atom_call(a, c)) < HOOK_STORE)
         __print_hex0(h->store[store], c);
   }
   return 0;
}

/***********************************************************/

CONTEXTCALL operator_if(atom_p a, context_p c)
{
   int_t err;
   atom_p if_atom, true_atom;
   DEBUG();
   if((if_atom = atom_child(a)) != NULL && (true_atom = atom_next(if_atom)) != NULL) {
      if ((err = (int_t)atom_call(if_atom, c)) < 0) {
         return -1;
      } else if(err) {
         return atom_call(true_atom, c);
      } else {
         if(true_atom->next) {
            return atom_call(true_atom->next, c);
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_not_if(atom_p a, context_p c)
{
   int_t err;
   atom_p if_atom, false_atom;
   DEBUG();
   if((if_atom = atom_child(a)) != NULL && (false_atom = atom_next(if_atom)) != NULL) {
      if ((err = (int_t)atom_call(if_atom, c)) < 0) {
         return -1;
      }
      if(!err) {
         return atom_call(false_atom, c);
      } else {
         if(false_atom->next) {
            return atom_call(false_atom->next, c);
         }
      }
   }
   return 0;
}

CONTEXTCALL operator_is_eq(atom_p a, context_p c)
{
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      return (atom_call(a, c) == atom_call(b, c));
   }
   return -1;
}

CONTEXTCALL operator_is_lt(atom_p a, context_p c)
{
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      return (atom_call(a, c) < atom_call(b, c));
   }
   return -1;
}

CONTEXTCALL operator_is_le(atom_p a, context_p c)
{
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      return (atom_call(a, c) <= atom_call(b, c));
   }
   return -1;
}

CONTEXTCALL operator_is_gt(atom_p a, context_p c)
{
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      return (atom_call(a, c) > atom_call(b, c));
   }
   return -1;
}

CONTEXTCALL operator_is_ge(atom_p a, context_p c)
{
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      return (atom_call(a, c) >= atom_call(b, c));
   }
   return -1;
}

CONTEXTCALL operator_is_null(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      return !atom_call(a, c);
   }
   return -1;
}

CONTEXTCALL operator_is_err(atom_p a, context_p c)
{
   DEBUG();
   if((a = atom_child(a)) != NULL) {
#ifdef __KERNEL__
      return IS_ERR((void *)atom_call(a, c));
#else
      return ((int_t)atom_call(a, c) < 0);
#endif
   }
   return -1;
}

/***********************************************************/

CONTEXTCALL operator_str_length(atom_p a, context_p c)
{
   uint_t addr;
   byte_p ptr;
   byte_t terminator;
   DEBUG();
   if((a = atom_child(a)) != NULL && (addr = atom_call(a, c)) != 0)
   {
      if((a = atom_next(a)) == NULL
            || (terminator = (byte_t) (0xff & atom_call(a, c))) == 0)
         return strlen((char *) addr);
      for(ptr = (byte_p) addr; *ptr != terminator; ptr++);
      return ptr - (byte_p)addr;
   }
   return 0;
}

CONTEXTCALL operator_str_equal(atom_p a, context_p c)
{
   byte_p data_a, data_b;
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      data_a = (byte_p) atom_call(a, c);
      data_b = (byte_p) atom_call(b, c);

      if(data_a == NULL)
         return (data_b == NULL) ? 0 : (uint_t)-1;

      if(data_b == NULL)
         return (uint_t)-1;

      if((b = atom_next(b)) != NULL)
         return (strncmp((char *) data_a, (char *) data_b, atom_call(b, c)) == 0);
      return (strcmp((char *) data_a, (char *) data_b) == 0);
   }
   return (uint_t)-1;
}

CONTEXTCALL operator_str_find(atom_p a, context_p c)
{
   char * str_a, * str_b;
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      str_a = (char *) atom_call(a, c);
      if(str_a == NULL)
         return (uint_t)-1;
      str_b = (char *) atom_call(b, c);
      if(str_b == NULL)
         return (uint_t)-1;
      return (uint_t)strstr(str_a, str_b);
   }
   return (uint_t)-1;
}

CONTEXTCALL operator_str_contains(atom_p a, context_p c)
{
   char * str_a, * str_b;
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      str_a = (char *) atom_call(a, c);
      if(str_a == NULL)
         return (uint_t)-1;
      str_b = (char *) atom_call(b, c);
      if(str_b == NULL)
         return (uint_t)-1;
      return (strstr(str_a, str_b) != NULL);
   }
   return (uint_t)-1;
}

CONTEXTCALL operator_str_starts(atom_p a, context_p c)
{
   char * str_a, * str_b;
   uint_t len_a, len_b;
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      str_a = (char *) atom_call(a, c);
      if(str_a == NULL)
         return (uint_t)-1;
      str_b = (char *) atom_call(b, c);
      if(str_b == NULL)
         return (uint_t)-1;
      len_a = strlen(str_a);
      len_b = strlen(str_b);
      if (len_a < len_b) return 0;
      return (strncmp(str_a, str_b, len_b) == 0);
   }
   return (uint_t)-1;
}

CONTEXTCALL operator_str_ends(atom_p a, context_p c)
{
   char * str_a, * str_b;
   uint_t len_a, len_b;
   atom_p b;
   DEBUG();
   if((a = atom_child(a)) != NULL && (b = atom_next(a)) != NULL) {
      str_a = (char *) atom_call(a, c);
      if(str_a == NULL)
         return (uint_t)-1;
      str_b = (char *) atom_call(b, c);
      if(str_b == NULL)
         return (uint_t)-1;
      len_a = strlen(str_a);
      len_b = strlen(str_b);
      if (len_a < len_b) return 0;
      return (strncmp(str_a + (len_a - len_b), str_b, len_b) == 0);
   }
   return (uint_t)-1;
}

/***********************************************************/

CONTEXTCALL operator_call(atom_p a, context_p c)
{
   void *callback_address;

   if((a = atom_child(a)) == NULL)
      return 0;
   if((callback_address = (void *) atom_call(a, c)) == NULL)
      return 0;
   DEBUG("calling code @ %p", callback_address);
   context_shot(c, callback_address);
   return 0;
}

CONTEXTCALL operator_print_ipv4(atom_p a, context_p c)
{
   uint_t ip;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      ip = atom_call(a, c);
      __print_uint(ip & 0xff, c, -1);
      __print_char('.', c);
      __print_uint((ip >> 8) & 0xff, c, -1);
      __print_char('.', c);
      __print_uint((ip >> 16) & 0xff, c, -1);
      __print_char('.', c);
      __print_uint((ip >> 24) & 0xff, c, -1);
   }
   return 0;
}

CONTEXTCALL operator_flip(atom_p a, context_p c)
{
   uint_t w;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      w = atom_call(a, c);
#ifdef __amd64__
      return
              ((w >> 56) & 0x00000000000000ff)
            | ((w >> 40) & 0x000000000000ff00)
            | ((w >> 24) & 0x0000000000ff0000)
            | ((w >> 8)  & 0x00000000ff000000)
            | ((w << 8)  & 0x000000ff00000000)
            | ((w << 24) & 0x0000ff0000000000)
            | ((w << 40) & 0x00ff000000000000)
            | ((w << 56) & 0xff00000000000000);
#else
      return
              ((w >> 24) & 0x000000ff)
            | ((w >> 8)  & 0x0000ff00)
            | ((w << 8)  & 0x00ff0000)
            | ((w << 24) & 0xff000000);
#endif
   }
   return 0;
}

CONTEXTCALL operator_while(atom_p a, context_p c)
{
   atom_p while_atom, exec_atom;
   int_t err = -1;
   DEBUG();
   if((while_atom = atom_child(a)) != NULL && (exec_atom = atom_next(while_atom)) != NULL) {
      for(; (err = (int_t)atom_call(while_atom, c)) > 0;) {
         if ((err = (int_t)atom_call(exec_atom, c)) != 0) break;
      }
   }
   return (err < 0) ? (uint_t)err : 0;
}

CONTEXTCALL operator_not_while(atom_p a, context_p c)
{
   atom_p while_atom, exec_atom;
   int_t err = -1;
   DEBUG();
   if((while_atom = atom_child(a)) != NULL && (exec_atom = atom_next(while_atom)) != NULL) {
      for(; (err = (int_t)atom_call(while_atom, c)) == 0;) {
         if ((err = (int_t)atom_call(exec_atom, c)) != 0) break;
      }
   }
   return (err < 0) ? (uint_t)err : 0;
}

CONTEXTCALL operator_repeat(atom_p a, context_p c)
{
   atom_p for_atom, exec_atom;
   uint_t i;
   int_t err = 0;
   DEBUG();
   if((for_atom = atom_child(a)) != NULL && (exec_atom = atom_next(for_atom)) != NULL) {
      i = atom_call(for_atom, c);
      if((int_t) i < 0)
         return 0;
      for(; i; i--) {
         if ((err = (int_t)atom_call(exec_atom, c)) != 0) break;
      }
   }
   return (err < 0) ? (uint_t)err : 0;
}

CONTEXTCALL operator_break(atom_p a, context_p c)
{
   DEBUG();
   return 1;
}

CONTEXTCALL operator_quit(atom_p a, context_p c)
{
   DEBUG();
   return (uint_t)-1;
}

CONTEXTCALL operator_timestamp(atom_p a, context_p c)
{
   DEBUG();
   return splinter_get_timestamp();
}

#ifdef __KERNEL__
CONTEXTCALL operator_task(atom_p a, context_p c)
{
   uint_t i;
   struct task_struct * t = NULL;
   DEBUG();
   if((a = atom_child(a)) != NULL) {
      if ((i = atom_call(a, c)) != 0) {
         // An example of how undecisive are linux kernel guys
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30))
         t = pid_task(find_get_pid(i), PIDTYPE_PID);
#else
         t = find_task_by_vpid(i);
#endif
#else
         t = find_task_by_pid_type(PIDTYPE_PID, i);
#endif
         DEBUG("pid=%lu task=%p", i, t);
      }
      return (uint_t) t;
   }

   return (uint_t) current;
}

CONTEXTCALL operator_is_pid(atom_p a, context_p c)
{
   uint_t i, pid, task_pid, level;
   struct task_struct * t = NULL;

   if ((a = atom_child(a)) != NULL && (pid = atom_call(a, c)) != 0) {
      level = 0;
      if ((a = atom_next(a)) != NULL)
         level = atom_call(a, c);
      for(i = 0, t = current; i <= level; i++, t = t->real_parent) {
         if (!t) return 0;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28))
         task_pid = task_pid_nr(t);
#else
         task_pid = t->pid;
#endif
         DEBUG("pid=%lu, task=%lu", pid, task_pid);
         if (task_pid == pid) return 1;
         if (task_pid == 1) return 0;
      }
   }

   return (uint_t)-1;
}

CONTEXTCALL operator_current(atom_p a, context_p c)
{
   uint_t new_current;
   DEBUG();

   if((a = atom_child(a)) != NULL) {
      if ((new_current = atom_call(a, c)) != 0) {
         DEBUG("setting current to = %p", (void *)new_current);
         percpu_write(current_task, (void *)new_current);
         return 0;
      }
   }

   DEBUG("current is = %p", (void *)current);
   return (uint_t) current;
}

CONTEXTCALL operator_pid(atom_p a, context_p c)
{
   struct task_struct *t;

   if((a = atom_child(a)) != NULL) {
      t = (struct task_struct *) atom_call(a, c);
   } else {
      t = current;
   }
   if(t) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28))
      return task_pid_nr(t);
#else
      return t->pid;
#endif
   }
   return 0;
}

CONTEXTCALL operator_uid(atom_p a, context_p c)
{
   struct task_struct *t;

   if((a = atom_child(a)) != NULL) {
      t = (struct task_struct *) atom_call(a, c);
   } else {
      t = current;
   }
   if(t) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28))
      return task_uid(t);
#else
      return t->uid;
#endif
   }
   return 0;
}

CONTEXTCALL operator_time(atom_p a, context_p c)
{
   struct timespec now;
   getnstimeofday(&now);
   return ((uint_t)now.tv_sec * 1000000000L + (uint_t)now.tv_nsec);
}

// This one is a combination of the above, and is meant to be
// a convienent method of getting a "signature" for output lines.
// Implemented as a timestamp/uid/pid string.
CONTEXTCALL operator_signature(atom_p a, context_p c)
{
   struct timespec now;
   uint_t pid, uid;
   getnstimeofday(&now);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28))
   pid = task_pid_nr(current);
   uid = (uint_t) task_uid(current);
#else
   pid = current->pid;
   uid = (uint_t) current->uid;
#endif
   __print_uint(now.tv_sec, c, 9);
   __print_char('.', c);
   __print_uint(now.tv_nsec, c, 9);
   __print_char('/', c);
   __print_uint(uid, c, -1);
   __print_char('/', c);
   __print_uint(pid, c, -1);
   return 0;
}
#else

// Dummy implementations in a non-kernel mode to satisfy linking.

CONTEXTCALL operator_task(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_is_pid(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_current(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_pid(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_uid(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_time(atom_p a, context_p c) {
   return 0;
}

CONTEXTCALL operator_signature(atom_p a, context_p c) {
   return 0;
}

#endif
