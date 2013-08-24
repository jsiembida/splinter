
#include "config.h"

#ifdef __i386__

#define WORD 4

#define R_AX eax
#define R_BX ebx
#define R_CX ecx
#define R_DX edx
#define R_SI esi
#define R_DI edi
#define R_BP ebp
#define R_SP esp

#define ARGREG1 eax
#define ARGREG2 edx
#define ARGREG3 ecx

#define MOVCMD movsd

#endif


#ifdef __amd64__

#define WORD 8

#define R_AX rax
#define R_BX rbx
#define R_CX rcx
#define R_DX rdx
#define R_SI rsi
#define R_DI rdi
#define R_BP rbp
#define R_SP rsp
#define R_8  r8
#define R_9  r9
#define R_10 r10
#define R_11 r11
#define R_12 r12
#define R_13 r13
#define R_14 r14
#define R_15 r15

#define ARGREG1 rdi
#define ARGREG2 rsi
#define ARGREG3 rdx

#define MOVCMD movsq

#endif
