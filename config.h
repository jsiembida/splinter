
#ifndef __SPLINTER_CONFIG_H__
#define __SPLINTER_CONFIG_H__ 1

#ifndef __i386__
  #ifndef __amd64__
    #error i386 and amd64 supported only...
  #endif
#endif

#define SPLINTER_VERSION "110828135300"

// #define SPLINTER_DEBUG 1
// #define SPLINTER_LOCK 1
// #define SPLINTER_TRUNCATE 1

#ifndef ERROR_BUFF
  #define ERROR_BUFF 1024
#endif

#ifndef CONTEXT_BUFF
  #define CONTEXT_BUFF 256
#endif

#ifndef CONTEXT_ARGS
  #define CONTEXT_ARGS 10
#endif

#ifndef CONTEXT_VARS
  #define CONTEXT_VARS 8
#endif

#ifndef CONTEXT_REGS
  #define CONTEXT_REGS 18
#endif

#ifndef MAX_ATOMS
  #define MAX_ATOMS 8192
#endif

#ifndef HOOK_STORE
  #define HOOK_STORE 16
#endif

#ifndef HOOK_LENGTH
  #define HOOK_LENGTH 32
#endif

#ifndef HOOK_TEXT
  #define HOOK_TEXT 128
#endif

#ifdef __i386__
  #define STRING_CHUNK 32
  #define STRING_BUFF  65536
#else
  #define STRING_CHUNK 64
  #define STRING_BUFF  65536
#endif

#ifndef IO_BUFF
  #define IO_BUFF (16 * 1024)
#endif

#ifndef MAX_SYMBOLS
  #define MAX_SYMBOLS 1024
#endif

#define DEFAULT_SOCKET "/var/run/.%l-splinter.%p"

#endif
