
/******************************************/

#include "splinter.h"

/******************************************/


byte_p ringbuf_data = NULL;
uint_t ringbuf_size = 0;
uint_t ringbuf_length = 0;
int_t ringbuf_head = 0;
uint_t ringbuf_dropped = 0;


int ringbuf_init(uint_t size) {
  uint_t i;
  debug(DEBUG_INF, "size = %lu", size);

  if (!size) return ringbuf_cleanup();
  if (ringbuf_data) return -1;
  for(i = 128; i < 64 * 1024 * 1024 && i < size; i <<= 1);
  size = i;
  if ((ringbuf_data = splinter_memory_alloc(size)) == NULL) {
    debug(DEBUG_ERR, "could not alloc ringbuffer");
    return -1;
  }
  ringbuf_size = size;
  debug(DEBUG_DBG, "ring buffer = %p - %p", ringbuf_data, ringbuf_data + size);
  return ringbuf_reset();
}


int ringbuf_reset(void) {
  DEBUG();
  ringbuf_length = 0;
  ringbuf_head = 0;
  ringbuf_dropped = 0;
  return 0;
}


int ringbuf_cleanup(void) {
  DEBUG();
  ringbuf_reset();
  ringbuf_size = 0;
  ringbuf_data = splinter_memory_free(ringbuf_data);
  return 0;
}


void ringbuf_dump(context_p c)
{
  ringbuf_write(c->buffer, &c->index, CONTEXT_BUFF,
    ringbuf_data, &ringbuf_head, &ringbuf_length, &ringbuf_dropped, ringbuf_size);
}


void ringbuf_read(byte_p dst, uint_p dst_length, uint_p dst_dropped,
  byte_p buf, int_p buf_head, uint_p buf_length, uint_p buf_dropped, uint_t buf_size)
{
  int i, head, mask;

  DEBUG("dst_length = %lu dst_dropped = %lu buf_head = %li buf_length = %lu buf_dropped = %lu buf_size = %lu",
        *dst_length, *dst_dropped, *buf_head, *buf_length, *buf_dropped, buf_size);

  *dst_dropped = *buf_dropped;

  i = *buf_length;
  if(!i) {
    *dst_length = 0;
    return;
  }

  *buf_dropped = 0;
  mask = buf_size - 1;

  head = *buf_head - i;
  if(head < 0)
    head += buf_size;

  if(i > *dst_length)
    i = *dst_length;
  *dst_length = i;
  *buf_length -= i;

  for(; i > 0; i--)
    *dst++ = buf[(head++) & mask];

  DEBUG("dst_length = %lu dst_dropped = %lu buf_head = %li buf_length = %lu buf_dropped = %lu buf_size = %lu",
        *dst_length, *dst_dropped, *buf_head, *buf_length, *buf_dropped, buf_size);
}


//
// This one is used upon exit from trampoline to dump the stack buffer into the main splinter buffer.
// It definitely needs optimization.
//
void ringbuf_write(byte_p src, uint_p src_index, uint_t src_size,
  byte_p buf, int_p buf_head, uint_p buf_length, uint_p buf_dropped, uint_t buf_size)
{
  int i = *src_index, l, k;
  int head = *buf_head, length = *buf_length, dropped = 0;
  int mask = buf_size - 1;

  DEBUG("src_index = %lu src_size = %lu buf_head = %li buf_length = %lu buf_dropped = %lu buf_size = %lu",
        *src_index, src_size, *buf_head, *buf_length, *buf_dropped, buf_size);

  if(i <= src_size) {
    length += i;
    if (buf_size - head >= i) {
      memcpy(buf + head, src, i);
      head += i;
      head &= mask;
    } else {
      for(; i > 0; i--) {
        buf[head++] = *src++;
        head &= mask;
      }
    }
  } else {
    dropped = i - src_size;
    length += src_size;
    i = i % src_size;
    l = src_size;
    k = src_size - 1;
    for(; l > 0; l--) {
      buf[head++] = src[i++];
      head &= mask;
      i &= k;
    }
  }
  if(length > buf_size) {
    dropped += length - buf_size;
    length = buf_size;
  }
  *buf_head = head;
  *buf_length = length;
  *buf_dropped += dropped;
  *src_index = 0;

  DEBUG("src_index = %lu src_size = %lu buf_head = %li buf_length = %lu buf_dropped = %lu buf_size = %lu",
        *src_index, src_size, *buf_head, *buf_length, *buf_dropped, buf_size);
}

