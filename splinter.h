
#ifndef __SPLINTER_H__
#define __SPLINTER_H__ 1

#include "config.h"

#define DEBUG_ALL 0
#define DEBUG_ERR 1
#define DEBUG_WRN 2
#define DEBUG_INF 3
#define DEBUG_DBG 4

extern int splinter_debug_level;
extern int splinter_test_mode;

#ifdef __KERNEL__

#include <asm/io.h>
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <asm/current.h>
#include <asm/percpu.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mman.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/preempt.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/preempt.h>
#include <linux/moduleloader.h>
#include <linux/cred.h>

#ifdef SPLINTER_DEBUG
  #define DEBUG(format, arg...) \
    printk(KERN_DEBUG "splinter:%s:%d " format "\n", __FUNCTION__, __LINE__, ##arg)
#else
  #define DEBUG(format, arg...) do {} while (0)
#endif

#define __debug(level, function, line, format, arg...) \
  if (splinter_debug_level >= level) { \
    printk("splinter:%s:%d " format "\n", function, line, ##arg); \
  }

#ifdef SPLINTER_LOCK
  #define splinter_lock_init(l)   spin_lock_init(&(l))
  #define splinter_lock_get(l)    spin_lock_bh(&(l))
  #define splinter_lock_put(l)    spin_unlock_bh(&(l))
#else
  #define splinter_lock_init(l)
  #define splinter_lock_get(l)
  #define splinter_lock_put(l)
#endif

#else /* __KERNEL__ */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/sched.h>


#ifdef SPLINTER_DEBUG
  #define DEBUG(format, arg...) \
    fprintf(stderr, "%s:%d " format "\n", __FUNCTION__, __LINE__, ##arg)
#else
  #define DEBUG(format, arg...) do {} while (0)
#endif

#define __debug(level, function, line, format, arg...) \
    if (splinter_debug_level >= level) { \
        fprintf(stderr, "%s:%d " format "\n", function, line, ##arg); \
    }

#ifdef SPLINTER_LOCK
  #define splinter_lock_init(l)   pthread_mutex_init(&(l), NULL)
  #define splinter_lock_get(l)    pthread_mutex_lock(&(l))
  #define splinter_lock_put(l)    pthread_mutex_unlock(&(l))
#else
  #define splinter_lock_init(l)
  #define splinter_lock_get(l)
  #define splinter_lock_put(l)
#endif

#endif /* userspace */


#define debug(level, format, arg...) \
    __debug(level, __FUNCTION__, __LINE__, format, ##arg)
#define splinter_error_set(format, arg...) \
    __splinter_error_set(__FUNCTION__, __LINE__, format, ##arg)
#define splinter_error_return(err, format, arg...) \
    { splinter_error_set(format, ##arg); return err; }


/*
 * (u)int8_t, (u)int32_t and (u)int64_t confuse gcc in
 * the context related to printf, hence those instead.
 */

typedef unsigned char byte_t;
typedef byte_t * byte_p;
#define byte_s sizeof(byte_t)

typedef signed long int int_t;
typedef int_t  * int_p;
#define int_s sizeof(int_t)

typedef unsigned long int uint_t;
typedef uint_t * uint_p;
#define uint_s sizeof(uint_t)

typedef int32_t * int32_p;
#define int32_s sizeof(int32_t)

typedef uint32_t * uint32_p;
#define uint32_s sizeof(uint32_t)

typedef int64_t * int64_p;
#define int64_s sizeof(int64_t)

typedef uint64_t * uint64_p;
#define uint64_s sizeof(uint64_t)

char * splinter_error_get(void);
int __splinter_error_set(const char *,  int, char *, ...);
void splinter_error_clear(void);

extern uint_t stats_memory_used;

void __splinter_memory_dump(const char *, int, const char *, byte_p);
#define splinter_memory_dump(msg, ptr) \
    __splinter_memory_dump(__FUNCTION__, __LINE__, msg, ptr);
void splinter_stats_dump(void);
void * splinter_memory_alloc(uint_t);
void * splinter_memory_free(void *);

extern uint_t stats_strings_used;
extern uint_t stats_strings_total_bytes;
extern uint_t stats_strings_free_bytes;
extern uint_t stats_strings_used_bytes;

int strings_init(uint_t);
int strings_cleanup(void);
int string_alloc(byte_p * s);
int string_free(byte_p * s);
int string_append(byte_p * s, char c);


/*
 * When compiled with -mregparm=3, gcc passes first 3 params
 * in eax, edx and ecx respectively, further parameters are
 * passed on the stack as in normal __cdecl convenction.

 * -mregparm=3
 * arg1: %eax
 * arg2: %edx
 * arg3: %ecx
 * argN: stack

 * -mregparm=2
 * arg1: %eax
 * arg2: %edx
 * argN: stack

 * -mregparm=1
 * arg1: %eax
 * argN: stack

 * -mregparm=0
 * argN: stack

 * Linux kernel is compiled with -mregparm=3, exception being
 * syscalls' entries which with asmlinkage are forced to follow
 * cdecl semantics. In amd64 mode a standard ABI is respected.
 */

#ifdef __i386__
  #define CONTEXTCALL __attribute__((regparm(3))) uint_t
#else
  #define CONTEXTCALL uint_t
#endif

/*
 * The structure of stack during the trampoline execution.
 *
 * The order of fields matters, placing regs first makes it
 * easy to take them off the stack, args go next and remain
 * on the stack during the whole cycle, they are not used
 * in exit-only scenario though. Variables and output buffer
 * as always being potentially in use go last and always
 * remain on the stack. This is hardcoded in assembly part,
 * any change will break things. An example minimal layout;

 *    18 words for registers
 *    10 words for arguments
 *     8 words for variables
 *     4 words for necessary stuff
 * =  40 words of overhead without a buffer
 * = 160 bytes in x32
 * = 320 bytes in x64

 * 18 registers are taken off the stack before giving up the
 * control, effectively no more than (10+8+4)words+context_buffer
 * reside on the stack.
 */

struct __context_t {
  uint_t reg0;   // eax
  uint_t reg1;   // ebx
  uint_t reg2;   // ecx
  uint_t reg3;   // edx
  uint_t reg4;   // esi
  uint_t reg5;   // edi
  uint_t reg6;   // ebp
  uint_t reg7;   // esp
  uint_t reg8;   // eip
  uint_t reg9;   // eflags

  // Regs 8 .. 15 are unused in i386, it is easier to have them
  // though and maintain one codebase for both, i386 and amd64.
  // Don't make any assumption about them in i386 mode, assembly
  // code still shuffles those fields around.

  uint_t reg10;  // r8
  uint_t reg11;  // r9
  uint_t reg12;  // r10
  uint_t reg13;  // r11
  uint_t reg14;  // r12
  uint_t reg15;  // r13
  uint_t reg16;  // r14
  uint_t reg17;  // r15

  // Effectively, total number of handled arguments is the below
  // plus number of arguments passed along in registers, which
  // depends on ABI and compilation flags (see above).

  uint_t arg0;
  uint_t arg1;
  uint_t arg2;
  uint_t arg3;
  uint_t arg4;
  uint_t arg5;
  uint_t arg6;
  uint_t arg7;
  uint_t arg8;
  uint_t arg9;

  uint_t var0;
  uint_t var1;
  uint_t var2;
  uint_t var3;
  uint_t var4;
  uint_t var5;
  uint_t var6;
  uint_t var7;

  byte_t buffer[CONTEXT_BUFF];

  uint_t index; // context IO buffer index
  uint_t link;  // link to arbitrary data
  uint_t ret;   // return address
  uint_t flags; // don't touch it, it is used in assembly code
};
typedef struct __context_t context_t;
typedef context_t * context_p;
#define context_s sizeof(context_t)

#define CONTEXT_FLAG_QUIT   0x100


struct __atom_t;
typedef struct __atom_t atom_t;
typedef atom_t * atom_p;
typedef void (*atom_free_callback_t)(atom_p);
typedef CONTEXTCALL (*atom_data_callback_t)(atom_p, context_p);
struct __atom_t {
  atom_free_callback_t free;
  atom_data_callback_t call;
  uint_t data;
  atom_p next;
};
#define atom_s sizeof(atom_t)


extern uint_t stats_atoms_total;
extern uint_t stats_atoms_total_bytes;
extern uint_t stats_atoms_free;
extern uint_t stats_atoms_free_bytes;
extern uint_t stats_atoms_used;
extern uint_t stats_atoms_used_bytes;

int atoms_init(uint_t);
int atoms_cleanup(void);
atom_p atom_alloc_plain(atom_data_callback_t, uint_t);
atom_p atom_alloc_string(atom_data_callback_t, char *, char *);
atom_p atom_alloc_list(atom_data_callback_t, atom_p);
atom_p atom_free(atom_p);

#define atom_child(a)   ((atom_p)((a)->data))
#define atom_next(a)    ((a)->next)
#define atom_call(a, c) ((a)->call((a), c))
#define atom_data(a)    ((a)->data)

typedef void (*expression_callback_t)(int);
atom_p parse_expression(char *, char *);
int validate_expression(char *, char *, expression_callback_t);

typedef void (*dumper_t)(context_p);

extern uint_t ringbuf_size;
extern byte_p ringbuf_data;
extern uint_t ringbuf_length;
extern int_t ringbuf_head;
extern uint_t ringbuf_dropped;

int ringbuf_init(uint_t size);
int ringbuf_reset(void);
int ringbuf_cleanup(void);
void ringbuf_read(byte_p dst, uint_p dst_length, uint_p dst_dropped,
  byte_p buf, int_p buf_head, uint_p buf_length, uint_p buf_dropped, uint_t buf_size);
void ringbuf_write(byte_p src, uint_p src_index, uint_t src_size,
  byte_p buf, int_p buf_head, uint_p buf_length, uint_p buf_dropped, uint_t buf_size);
void ringbuf_dump(context_p);


/*
 * Basic internal operators, only used by parser.
 * for primitive atoms, numbers, strings, etc.
 */
CONTEXTCALL operator_null(atom_p, context_p);
CONTEXTCALL operator_value(atom_p, context_p);
CONTEXTCALL operator_string(atom_p, context_p);
CONTEXTCALL operator_hex(atom_p, context_p);
CONTEXTCALL operator_int(atom_p, context_p);
CONTEXTCALL operator_uint(atom_p, context_p);
CONTEXTCALL operator_exec(atom_p, context_p);

/*
 * Set of elemental arithmetic and logic operators
 */
CONTEXTCALL operator_add(atom_p, context_p);
CONTEXTCALL operator_sub(atom_p, context_p);
CONTEXTCALL operator_mul(atom_p, context_p);
CONTEXTCALL operator_div(atom_p, context_p);

CONTEXTCALL operator_and(atom_p, context_p);
CONTEXTCALL operator_or(atom_p, context_p);
CONTEXTCALL operator_not(atom_p, context_p);

CONTEXTCALL operator_bit_and(atom_p, context_p);
CONTEXTCALL operator_bit_or(atom_p, context_p);
CONTEXTCALL operator_bit_xor(atom_p, context_p);
CONTEXTCALL operator_bit_not(atom_p, context_p);
CONTEXTCALL operator_bit_shl(atom_p, context_p);
CONTEXTCALL operator_bit_shr(atom_p, context_p);

/*
 * Conditional operators
 */
CONTEXTCALL operator_if(atom_p, context_p);
CONTEXTCALL operator_not_if(atom_p, context_p);
CONTEXTCALL operator_is_eq(atom_p, context_p);
CONTEXTCALL operator_is_lt(atom_p, context_p);
CONTEXTCALL operator_is_le(atom_p, context_p);
CONTEXTCALL operator_is_gt(atom_p, context_p);
CONTEXTCALL operator_is_ge(atom_p, context_p);
CONTEXTCALL operator_is_null(atom_p, context_p);
CONTEXTCALL operator_is_err(atom_p, context_p);

/*
 * Registers, pointers, variables etc...
 */
CONTEXTCALL operator_return(atom_p, context_p);
CONTEXTCALL operator_register(atom_p, context_p);
CONTEXTCALL operator_argument(atom_p, context_p);
CONTEXTCALL operator_variable(atom_p, context_p);
CONTEXTCALL operator_memory(atom_p, context_p);
CONTEXTCALL operator_store(atom_p, context_p);

/*
 * Print operators, those guys show the stuff.
 */
CONTEXTCALL operator_print_char(atom_p, context_p);
CONTEXTCALL operator_print_byte(atom_p, context_p);
CONTEXTCALL operator_print_hex(atom_p, context_p);
CONTEXTCALL operator_print_hex0(atom_p, context_p);
CONTEXTCALL operator_print_int(atom_p, context_p);
CONTEXTCALL operator_print_uint(atom_p, context_p);
CONTEXTCALL operator_print_chars(atom_p, context_p);
CONTEXTCALL operator_print_bytes(atom_p, context_p);
CONTEXTCALL operator_print_uints(atom_p, context_p);
CONTEXTCALL operator_print_string(atom_p, context_p);
CONTEXTCALL operator_print_argv(atom_p, context_p);

CONTEXTCALL operator_print_ipv4(atom_p, context_p);

CONTEXTCALL operator_buffer_flush(atom_p, context_p);
CONTEXTCALL operator_buffer_clear(atom_p, context_p);

/*
 * Extra stuff, loops, external code calls
 * plus some conveniece operators.
 */
CONTEXTCALL operator_repeat(atom_p, context_p);
CONTEXTCALL operator_while(atom_p, context_p);
CONTEXTCALL operator_not_while(atom_p, context_p);
CONTEXTCALL operator_break(atom_p, context_p);
CONTEXTCALL operator_quit(atom_p, context_p);

CONTEXTCALL operator_flip(atom_p, context_p);
CONTEXTCALL operator_call(atom_p, context_p);
CONTEXTCALL operator_timestamp(atom_p, context_p);

CONTEXTCALL operator_str_equal(atom_p, context_p);
CONTEXTCALL operator_str_length(atom_p, context_p);
CONTEXTCALL operator_str_starts(atom_p, context_p);
CONTEXTCALL operator_str_ends(atom_p, context_p);
CONTEXTCALL operator_str_find(atom_p, context_p);
CONTEXTCALL operator_str_contains(atom_p, context_p);

/*
 * Kernel specific operators.
 */
// #ifdef __KERNEL__
CONTEXTCALL operator_pid(atom_p, context_p);
CONTEXTCALL operator_uid(atom_p, context_p);
CONTEXTCALL operator_task(atom_p, context_p);
CONTEXTCALL operator_time(atom_p, context_p);
CONTEXTCALL operator_signature(atom_p, context_p);
CONTEXTCALL operator_current(atom_p, context_p);
CONTEXTCALL operator_is_pid(atom_p, context_p);
// #endif


/*
 * Hook struct, aligned to take 1024 bytes.
 */

#ifndef TRAMPOLINE_LENGTH
  #define TRAMPOLINE_LENGTH \
    (1024 \
     - uint32_s \
     - int32_s \
     - uint32_s \
     - uint32_s \
     - 5 * uint_s \
     - HOOK_LENGTH * byte_s \
     - 4 * sizeof(void *) \
     - HOOK_TEXT * byte_s \
     - HOOK_STORE * uint_s \
    )
#endif

struct __hook_t;
typedef struct __hook_t hook_t;
typedef hook_t * hook_p;

struct __hook_t {
  uint32_t id;       // unique id for each hook, entirely for
                     // identification purpose
  int32_t used;      // used > 0    - in use
                     // used == 0   - unused, free to be taken
                     // used < 0    - in 'limbo', don't touch it
  uint32_t refcount; // Reference counter, it is atomically increased
                     // upon entry to the hook, decreased upon leave.
                     // From C code it is only examined to check if
                     // any thread is running through it.
                     // No overflow check is performed.
  uint32_t enabled;

  uint_t address;
  uint_t hits;
  uint_t dropped;
  uint_t hooked_entry;
  uint_t hooked_size;
  byte_t hooked_bytes[HOOK_LENGTH];
  dumper_t dumper;
  atom_p entry_chain;
  atom_p exit_chain;
  hook_p next;
  /*
   * Dangeours to place the store buffer right before trampoline
   * code, if overflown, trampoline is first to be littered.
   */
  byte_t text[HOOK_TEXT];
  uint_t store[HOOK_STORE];
  byte_t trampoline[TRAMPOLINE_LENGTH];
};

typedef void (*trigger_t)(void);

#define hook_s sizeof(hook_t)

hook_p hook_install(uint_t, char *, char *, char *, dumper_t, int);
int hook_uninstall(int);


CONTEXTCALL context_call(atom_p *, hook_p, context_p);
CONTEXTCALL context_close(hook_p, context_p);
/*
 * An external assembly function see shot.S
 */
CONTEXTCALL context_shot(context_p, void *);

extern uint_t stats_hooks_total;
extern uint_t stats_hooks_free;
extern uint_t stats_hooks_used;
extern uint_t stats_hooks_limbo;
extern uint_t stats_hooks_total_bytes;
extern uint_t stats_hooks_free_bytes;
extern uint_t stats_hooks_used_bytes;
extern uint_t stats_hooks_limbo_bytes;

int hooks_init(uint_t, trigger_t, trigger_t);
int hooks_cleanup(void);
hook_p hook_find(uint_t);
hook_p hook_get(uint_t);
int hook_in_use(hook_p);
hook_p hook_alloc(void);
hook_p hook_free(hook_p);


extern uint_t stats_symbols_total;
extern uint_t stats_symbols_free;
extern uint_t stats_symbols_used;
extern uint_t stats_symbols_total_bytes;
extern uint_t stats_symbols_free_bytes;
extern uint_t stats_symbols_used_bytes;
extern uint_t stats_symbols_hash_size;
extern uint_t stats_symbols_hash_bytes;

int symbols_init(uint_t);
int symbols_cleanup(void);
uint_t splinter_get_symbol(char *);
uint_t splinter_find_symbol(char *);
char * splinter_find_variable(char *);

uint_t splinter_get_timestamp(void);
int splinter_handle_request(char *, int, char *, int);

CONTEXTCALL atomic_swap(void *, void *);

struct __disass_t {
  byte_p code;
  byte_t parsed_buff[32];
  int parsed_len;
  int branch_opcode;
  int branch_offset;
  int_t branch_address;
};
typedef struct __disass_t disass_t;
typedef disass_t * disass_p;
#define disass_s sizeof(disass_t)

int splinter_code_disass(byte_p, disass_p);
int splinter_code_copy(byte_p, disass_p);
int splinter_code_patch(byte_p, disass_p);

/*
 * Assembly routines, we need their addresses
 * so that we can reach for the opcodes and drop
 * them into the trampoline.
 */
extern void __splinter_entry_start(void);
extern void __splinter_entry_finish(void);

extern void __splinter_exit_start1(void);
extern void __splinter_exit_finish1(void);
extern void __splinter_exit_start2(void);
extern void __splinter_exit_finish2(void);

extern void __splinter_both_start1(void);
extern void __splinter_both_finish1(void);
extern void __splinter_both_start2(void);
extern void __splinter_both_finish2(void);

#endif // __SPLINTER_H__

