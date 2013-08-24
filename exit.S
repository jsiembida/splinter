
#include "asm.h"

.text

.globl __splinter_exit_start1
__splinter_exit_start1:

  pushf
  push   %R_AX
  mov    $0xDEAFFACE, %R_AX
  lock   incl (%R_AX)
  xor    %R_AX,   %R_AX
  push   %R_AX
  push   %R_AX
  mov    4 * WORD (%R_SP),   %R_AX
  xchg   %R_AX,   2 * WORD (%R_SP)
  push   %R_AX

  sub    $CONTEXT_BUFF + (CONTEXT_ARGS + CONTEXT_VARS - 1) * WORD,   %R_SP
  push   %R_DI
  push   %R_SI
  push   %R_CX

  mov    %R_SP,   %R_SI
  add    $CONTEXT_BUFF + WORD * (8 + CONTEXT_ARGS + CONTEXT_VARS),   %R_SI
  mov    %R_SP,   %R_DI
  add    $WORD * 3,   %R_DI
  mov    $CONTEXT_ARGS,   %R_CX
  cld
  rep    MOVCMD

  pop    %R_CX
  pop    %R_SI
  pop    %R_DI
  mov    CONTEXT_BUFF + WORD * (3 + CONTEXT_ARGS + CONTEXT_VARS) (%R_SP),   %R_AX
  push   %R_AX
  popf
  mov    $0xDEADBEEF,   %R_AX
  push   %R_AX
  mov    CONTEXT_BUFF + WORD * (CONTEXT_ARGS + CONTEXT_VARS) (%R_SP),   %R_AX

.globl __splinter_exit_finish1
__splinter_exit_finish1:



.globl __splinter_exit_start2
__splinter_exit_start2:

#ifdef __amd64__
  push   %R_15
  push   %R_14
  push   %R_13
  push   %R_12
  push   %R_11
  push   %R_10
  push   %R_9
  push   %R_8
#endif

#ifdef __i386__
  push   %R_AX
  push   %R_AX
  push   %R_AX
  push   %R_AX
  push   %R_AX
  push   %R_AX
  push   %R_AX
  push   %R_AX
#endif

  pushf
  push   %R_AX
  xor    %R_AX,   %R_AX
  mov    %R_AX,   CONTEXT_BUFF + (13 + CONTEXT_ARGS + CONTEXT_VARS) * WORD (%R_SP)
  mov    %R_SP,   %R_AX
  add    $CONTEXT_BUFF + (14 + CONTEXT_ARGS + CONTEXT_VARS) * WORD,   %R_AX
  push   %R_AX
  push   %R_BP
  push   %R_DI
  push   %R_SI
  push   %R_DX
  push   %R_CX
  push   %R_BX
  mov    $0xDEADBEEF,   %R_AX
  xchg   %R_AX,   7 * WORD (%R_SP)
  push   %R_AX

  mov    %R_SP,   %ARGREG3
  mov    $0xBEADFACE,   %ARGREG2
  mov    $0xCAFEBABE,   %ARGREG1
  # The following will produce opcodes e8 ce fa ed fe (call 0xFEEDFACE)
  .byte  0xe8, 0xce, 0xfa, 0xed, 0xfe
  mov    %R_SP,   %ARGREG2
  mov    $0xBEADFACE,   %ARGREG1
  # The following will produce opcodes e8 ad de ad de (call 0xDEADDEAD)
  .byte  0xe8, 0xad, 0xde, 0xad, 0xde

  mov    %R_SP,   %R_DI
  add    $CONTEXT_BUFF + (CONTEXT_VARS + CONTEXT_ARGS + CONTEXT_REGS + 5) * WORD,   %R_DI
  mov    %R_SP,   %R_SI
  add    $CONTEXT_REGS * WORD,   %R_SI
  mov    $CONTEXT_ARGS,   %R_CX
  cld
  rep    MOVCMD

  pop    %R_AX
  pop    %R_BX
  pop    %R_CX
  pop    %R_DX
  pop    %R_SI
  pop    %R_DI
  add    $WORD * 3,   %R_SP
  xchg   %R_AX,   (%R_SP)
  mov    %R_AX,   CONTEXT_BUFF + WORD * (CONTEXT_ARGS + CONTEXT_VARS + 12) (%R_SP)
  pop    %R_AX

#ifdef __amd64__
  pop    %R_8
  pop    %R_9
  pop    %R_10
  pop    %R_11
  pop    %R_12
  pop    %R_13
  pop    %R_14
  pop    %R_15
#endif

#ifdef __i386__
  mov    %R_AX,   WORD * 7 (%R_SP)
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
  pop    %R_AX
#endif

  add    $CONTEXT_BUFF + WORD * (CONTEXT_ARGS + CONTEXT_VARS + 3),   %R_SP
  push   %R_AX
  mov    $0xDEAFFACE, %R_AX
  lock   decl (%R_AX)
  pop    %R_AX
  popf
  ret

.globl __splinter_exit_finish2
__splinter_exit_finish2:

