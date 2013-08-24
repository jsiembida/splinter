
/******************************************/

#include "splinter.h"

/******************************************/


//
// Profligate, especially in 64bit. Presumably, we could
// make length 2 bytes long only, the whole is not intended
// to handle long strings anyway.
//
struct __string {
  byte_p * pointer;
  uint_t length;
  byte_t buffer[0];
};
typedef struct __string string_t;
typedef string_t * string_p;
#define string_s sizeof(string_t)

#define __string_struct_pointer(s) \
  ((string_p)(((byte_p)(s)) - string_s))

#define __string_struct_length(s) \
  (string_s + (s)->length + 1)

#define __string_struct_alignment(s)  \
  ((__string_struct_length(s) % STRING_CHUNK) \
    ? (STRING_CHUNK - (__string_struct_length(s) % STRING_CHUNK)) : 0)

#define __string_struct_next(s)   \
  ((string_p) (((byte_p)(s)) \
    + __string_struct_length(s) \
    + __string_struct_alignment(s)))

#define __string_struct_valid(s) \
  ((((byte_p)(s)) >= __strings_buffer) \
    && (((byte_p)(s)) < __strings_first_free) \
    && ((string_p)(s))->pointer)


static byte_p __strings_buffer = NULL;
static byte_p __strings_first_free = NULL;
static byte_p __strings_last_free = NULL;
uint_t stats_strings_used = 0;
uint_t stats_strings_total_bytes = 0;
uint_t stats_strings_free_bytes = 0;
uint_t stats_strings_used_bytes = 0;


int strings_init(uint_t size) {
  debug(DEBUG_DBG, "size = %lu", size);
  if (!size) return strings_cleanup();
  if (size < STRING_CHUNK) return -1;
  if (__strings_buffer) return -1;
  if ((__strings_buffer = splinter_memory_alloc(size)) == NULL) {
    debug(DEBUG_ERR, "could not alloc strings buffer");
    return -1;
  }
  __strings_first_free = __strings_buffer;
  __strings_last_free = __strings_buffer + size;
  stats_strings_total_bytes = stats_strings_free_bytes = size;
  stats_strings_used = stats_strings_used_bytes = 0;
  debug(DEBUG_DBG, "strings buffer = %p - %p", __strings_buffer, ((byte_p)__strings_buffer) + size);
  return 0;
}


int strings_cleanup(void) {
  if (!__strings_buffer) return -1;
  DEBUG();
  __strings_buffer = splinter_memory_free(__strings_buffer);
  __strings_first_free = __strings_last_free = NULL;
  stats_strings_total_bytes = stats_strings_free_bytes =
    stats_strings_used_bytes = stats_strings_used = 0;
  return 0;
}


static int __string_alloc(byte_p * s, int length) {
  string_p str;
  DEBUG();

  if (!s) return -1;
  if (*s) return -1;

  if (__strings_last_free - __strings_first_free < length) return -1;

  memset(__strings_first_free, 0, length);
  str = (string_p)__strings_first_free;
  str->pointer = s;
  *s = str->buffer;

  __strings_first_free += length;

  stats_strings_used += 1;
  stats_strings_free_bytes -= length;
  stats_strings_used_bytes += length;

  return 0;
}


int string_alloc(byte_p * s) {
  DEBUG();
  return __string_alloc(s, STRING_CHUNK);
}


static int __string_shift(byte_p * dst, string_p * str) {
  uint_t length;
  uint_t align;
  string_p curr;
  string_p next;

  curr = *str;
  if (!__string_struct_valid(curr)) return -1;

  DEBUG("[%s]", curr->buffer);

  length = __string_struct_length(curr);
  align  = __string_struct_alignment(curr);
  next   = __string_struct_next(curr);

  *(curr->pointer) = NULL;
  memmove(*dst, curr, length);
  if (align) memset(*dst + length, 0, align);
  curr = (string_p)(*dst);
  *(curr->pointer) = curr->buffer;
  *dst += length + align;
  *str = next;

  return 0;
}


static byte_p __strings_shift(byte_p dst, string_p str) {
  DEBUG();
  while(__string_shift(&dst, &str) == 0);
  return dst;
}


int string_free(byte_p * s) {
  string_p str, next_str;
  uint_t length;
  DEBUG("[%s]", *s);

  if (!s) return -1;
  if (!*s) return -1;

  str = __string_struct_pointer(*s);
  if (!__string_struct_valid(str)) return -1;

  *(str->pointer) = NULL;
  next_str = __string_struct_next(str);
  length = ((byte_p)next_str) - ((byte_p)str);
  __strings_first_free = __strings_shift((byte_p)str, next_str);

  stats_strings_used -= 1;
  stats_strings_free_bytes += length;
  stats_strings_used_bytes -= length;

  return 0;
}


int string_append(byte_p * s, char c) {
  string_p str, tmp_str;
  byte_p tmp_s = NULL;
  uint_t length;
  uint_t align;
  DEBUG();

  if (!s) return -1;
  if (!*s) return -1;

  str = __string_struct_pointer(*s);
  if (!__string_struct_valid(str)) return -1;

  align = __string_struct_alignment(str);
  if (align > 0) {
    str->buffer[str->length++] = c;
    str->buffer[str->length] = 0;
    return 0;
  }

  length = __string_struct_length(str);
  if (__string_alloc(&tmp_s, length + STRING_CHUNK)) {
    return -1;
  }
  tmp_str = __string_struct_pointer(tmp_s);
  memcpy(tmp_str->buffer, str->buffer, str->length);
  tmp_str->length = str->length;
  tmp_str->buffer[tmp_str->length++] = c;
  tmp_str->buffer[tmp_str->length] = 0;
  tmp_str->pointer = str->pointer;
  *(tmp_str->pointer) = tmp_str->buffer;

  str->pointer = &tmp_s;
  *(str->pointer) = str->buffer;
  string_free(&tmp_s);

  return 0;
}


// Testing code

/*
void __new(byte_p * s, int l) {
  int i;
  *s = NULL;
  string_alloc(s);
  for(i = 0; i < l; i++)
    string_append(s, '0' + i);
}

void __add(byte_p * s, int l) {
  int i;
  for(i = 0; i < l; i++)
    string_append(s, 'a' + i);
}

int main(int argc, char ** argv) {
  byte_p s1, s2, s3, s4, s5, s6;
  __new(&s1, 4);
  __new(&s2, 5);
  __new(&s3, 1);
  __new(&s4, 2);

  string_free(&s2);
  string_free(&s3);
  __new(&s5, 6);
  string_free(&s1);
  __new(&s2, 20);
  string_free(&s4);
  __new(&s6, 12);
  __add(&s5, 10);
  __add(&s2, 7);

  string_free(&s1);
  string_free(&s2);
  string_free(&s3);
  string_free(&s4);
  string_free(&s5);
  string_free(&s6);

  return 0;
}
*/

