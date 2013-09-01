
#include "splinter.h"

/*

1. In a regular x32 mode, a jump instruction takes one byte
   of opcode (0xe9) and four bytes of a relative jump.
   The jump is relative to an address of an instruction
   immediately following the jump. That is, we need 5 extra
   bytes to redirect execution flow:

   0:	e9 00 00 00 00       	jmp    0x5

2. In an x64 mode the x32 jump is still available but there is
   no analogous 64bit jump. Meaning, there is no direct way to
   jump beyond 32bit boundary in 64bit which implies, code is
   still limited to 4GB. Even though one may not need this big
   chunk of code, virtual memory can be mapped across over 4GB
   boundaries even though physically code takes less.
   x64 linux kernel e.g. separates its code (and modules) from
   its data (and that of modules) away by more than 4GB.
   Therefore if you want to jump from code in linux kernel to
   data you need to work it around.

   Here is a trick that unfortunately takes 19 bytes, at present
   splinter does not use it though. In the kernelspace another
   trick is used to ensure that trampolines are close enough to
   the kernel code so as to make x32 jumps sufficient.

   0:	50                   	push   %rax
   1:	50                   	push   %rax
   2:	48 b8 ef cd ab 90 78 	mov    $0x1234567890abcdef,%rax
   9:	56 34 12
   c:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  11:	58                   	pop    %rax
  12:	c3                   	retq

*/

static void __set_page_rwx(uint_t addr) {
#ifdef __KERNEL__
  int page = PAGE_SIZE;
#else
  int page = sysconf(_SC_PAGE_SIZE);
#endif
  int mask = ~(page - 1);
  addr &= (uint_t)mask;

  debug(DEBUG_DBG, "setting rwx %p - %p", (void *)addr, (void *)(addr + page + page));

#ifdef __KERNEL__
  set_memory_rw(addr, 2);
  set_memory_x(addr, 2);
#else
  mprotect((void *)addr, page + page, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
}

static byte_p __put_branch(byte_t opcode, byte_p code, byte_p ptr) {
  byte_t buf[8];
  uint_t offset;

  if(!code || !ptr) return NULL;

  __set_page_rwx((uint_t)code);
  __set_page_rwx((uint_t)ptr);

  debug(DEBUG_DBG, "putting branch %p -> %p", code, ptr);
  offset = ptr - code - 5;
  memcpy(buf, code, 8);
  buf[0] = opcode;
  *((uint32_p)(buf + 1)) = (uint32_t)offset;
  atomic_swap(buf, code);
  return code + 5;
}

#define __put_jump(code, ptr) __put_branch(0xe9, code, ptr)
#define __put_call(code, ptr) __put_branch(0xe8, code, ptr)

static void replace_values(byte_p code, uint_t old_val, uint_t new_val, int len, int relative) {
  uint_t cur_val;

  while(len > 0) {
    if (relative)
      cur_val = *((uint32_p)code) & 0xffffffff;
    else
      cur_val = *((uint_p) code);

    if(cur_val == old_val) {
      debug(DEBUG_DBG, "found %p @ %p replacing with %p", (void *)old_val, code, (void *)new_val);
      if (relative) {
        cur_val = (new_val - ((uint_t) code) - 4) & 0xffffffff;
        *((uint32_p)code) = (uint32_t)(cur_val & 0xffffffff);
        code += 4;
        len -= 4;
      } else {
        *((uint_p) code) = new_val;
        code += uint_s;
        len -= uint_s;
      }
    } else {
      len--;
      code++;
    }
  }
}

#define replace_absolute(hex, val) replace_values(ptr, 0x##hex, (uint_t)(val), len, 0)
#define replace_relative(hex, val) replace_values(ptr, 0x##hex, (uint_t)(val), len, 1)

static byte_p __hook_install_entry(hook_p h, disass_p disass_context) {
  byte_p code, ptr;
  int len;

  code = (byte_p) h->address;
  ptr = h->trampoline;
  len = ((byte_p)__splinter_entry_finish) - ((byte_p)__splinter_entry_start);
  memcpy(ptr, (byte_p)__splinter_entry_start, len);
  replace_absolute(DEAFFACE, &(h->refcount));
  replace_absolute(DEADBEEF, code);
  replace_absolute(BEADFACE, h);
  replace_absolute(CAFEBABE, &(h->entry_chain));
  replace_relative(FEEDFACE, context_call);
  replace_relative(DEADDEAD, context_close);
  ptr += len;
  h->hooked_entry = (uint_t)ptr;
  ptr += splinter_code_patch(ptr, disass_context);
  return __put_jump(ptr, code + h->hooked_size);
}

static byte_p __hook_install_exit(hook_p h, disass_p disass_context) {
  byte_p code, ptr;
  int len;

  code = (byte_p) h->address;
  ptr = h->trampoline;
  len = ((byte_p)__splinter_exit_finish1) - ((byte_p)__splinter_exit_start1);
  memcpy(ptr, (byte_p)__splinter_exit_start1, len);
  ptr += len;
  h->hooked_entry = (uint_t)ptr;
  ptr += splinter_code_patch(ptr, disass_context);
  ptr = __put_jump(ptr, code + h->hooked_size);
  replace_values(h->trampoline, 0xDEAFFACE, (uint_t) &(h->refcount), len, 0);
  replace_values(h->trampoline, 0xDEADBEEF, (uint_t) ptr, len, 0);

  len = ((byte_p)__splinter_exit_finish2) - ((byte_p)__splinter_exit_start2);
  memcpy(ptr, (byte_p)__splinter_exit_start2, len);
  replace_absolute(DEAFFACE, &(h->refcount));
  replace_absolute(DEADBEEF, code);
  replace_absolute(BEADFACE, h);
  replace_absolute(CAFEBABE, &(h->exit_chain));
  replace_relative(FEEDFACE, context_call);
  replace_relative(DEADDEAD, context_close);
  return ptr + len;
}

static byte_p __hook_install_both(hook_p h, disass_p disass_context)
{
  byte_p code, ptr;
  int len;

  code = (byte_p) h->address;
  code = (byte_p) h->address;
  ptr = h->trampoline;
  len = ((byte_p)__splinter_both_finish1) - ((byte_p)__splinter_both_start1);
  memcpy(ptr, (byte_p)__splinter_both_start1, len);
  replace_absolute(DEAFFACE, &(h->refcount));
  replace_absolute(DEADBEEF, code);
  replace_absolute(BEADFACE, h);
  replace_absolute(CAFEBABE, &(h->entry_chain));
  replace_relative(FEEDFACE, context_call);
  ptr += len;

  h->hooked_entry = (uint_t)ptr;
  ptr += splinter_code_patch(ptr, disass_context);
  ptr = __put_jump(ptr, code + h->hooked_size);

  replace_values(h->trampoline, 0xDEADBABE, (uint_t) ptr, len, 0);

  len = ((byte_p)__splinter_both_finish2) - ((byte_p)__splinter_both_start2);
  memcpy(ptr, __splinter_both_start2, len);
  replace_absolute(DEAFFACE, &(h->refcount));
  replace_absolute(DEADBEEF, code);
  replace_absolute(BEADFACE, h);
  replace_absolute(CAFEBABE, &(h->exit_chain));
  replace_relative(FEEDFACE, context_call);
  replace_relative(DEADDEAD, context_close);
  return ptr + len;
}

hook_p hook_install(uint_t address, char * entry_expression, char * exit_expression, char * hook_text, dumper_t dumper, int test_mode)
{
  byte_p ptr;
  int i;
  uint_t hooked_size = 0;
  atom_p entry_chain = NULL;
  atom_p exit_chain = NULL;
  hook_p h = NULL;
  disass_t disass_context;

  if (!address)
      splinter_error_return(NULL, "NULL cannot be hooked");

  if (!entry_expression && !exit_expression)
      splinter_error_return(NULL, "entry/exit hook expression need to be provided");

  if (hook_find(address))
      splinter_error_return(NULL, "%lx is already hooked", address);

  // We need at least 5 bytes of room, that is a relative jmp length.
  if ((i = splinter_code_disass((byte_p)address, &disass_context)) < 0)
    return NULL;
  if((hooked_size = (uint_t)i) < 5)
    splinter_error_return(NULL, "detected only %lu bytes of code header", hooked_size);
  if(hooked_size > HOOK_LENGTH)
    splinter_error_return(NULL, "disassembling returned a bizarre value of %lu bytes", hooked_size);

  if (entry_expression) {
    if ((entry_chain = parse_expression("entry expression -", entry_expression)) == NULL)
        return NULL;
  }
  if (exit_expression) {
    if ((exit_chain = parse_expression("exit expression -", exit_expression)) == NULL) {
      entry_chain = atom_free(entry_chain);
      return NULL;
    }
  }

  if ((h = hook_alloc()) == NULL) {
    exit_chain = atom_free(exit_chain);
    entry_chain = atom_free(entry_chain);
    splinter_error_return(NULL, "couldn't alloc a new hook");
  }

  debug(DEBUG_DBG, "hook = %p id = %lu", h, (uint_t)h->id);
  h->address = address;
  h->hooked_size = hooked_size;
  h->entry_chain = entry_chain;
  h->exit_chain = exit_chain;
  h->dumper = dumper;
  h->enabled = 0;

  i = 0;
  if (hook_text) i = strlen(hook_text);
  if (i > HOOK_TEXT - 1) i = HOOK_TEXT - 1;
  if (i) strncpy((char *)h->text, hook_text, i);
  h->text[i] = 0;

  // Copy the original N bytes from where the hook is to be installed.
  // Even if N < 8, we copy 8 bytes, this is a required minimum for
  // the atomic CMPXCHG copy on unhooking.
  memcpy(h->hooked_bytes, (void *)address, hooked_size > 8 ? hooked_size : 8);
  for(i = 0; i < HOOK_STORE; h->store[i++] = 0);
  if(entry_chain != NULL && exit_chain == NULL)
    ptr = __hook_install_entry(h, &disass_context);
  else if(entry_chain == NULL && exit_chain != NULL)
    ptr = __hook_install_exit(h, &disass_context);
  else
    ptr = __hook_install_both(h, &disass_context);

  // Now install the actual hook...
  debug(DEBUG_DBG, "trampoline = %p - %p (%ld bytes)", h->trampoline, ptr, (uint_t)((byte_p)ptr - (byte_p)h->trampoline));
  if (!test_mode) {
    __put_jump((byte_p)h->address, h->trampoline);
    debug(DEBUG_INF, "hooked %p -> %p", (void *)h->address, h->trampoline);
  } else {
    debug(DEBUG_INF, "test mode, skipping the actual hooking");
  }
  return h;
}

int hook_uninstall(int n)
{
  hook_p h = hook_get(n);

  if (!h)
    splinter_error_return(-1, "hook number %d not found", n);

  if (!hook_in_use(h))
    splinter_error_return(-1, "hook number %d is unused", n);

  debug(DEBUG_INF, "%lu bytes -> %p", h->hooked_size, (void *)h->address);
  // In fact we copy back 8 bytes, in an atomic fashion with a CMPXCHG command.
  // That is ok since only first 5 bytes are really altered upon hook installation.
  atomic_swap((void *)h->hooked_bytes, (void *)h->address);
  hook_free(h);

  return 0;
}
