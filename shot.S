

#include "asm.h"


.globl context_shot
context_shot:


#ifdef __i386__


  push   %ebp
  push   %edi
  push   %esi
  push   %edx
  push   %ecx
  push   %ebx
  push   %eax

  sub    $WORD * CONTEXT_ARGS,   %esp
  mov    %esp,   %edi
  mov    %eax,   %esi
  add    $WORD * CONTEXT_REGS,   %esi
  mov    $CONTEXT_ARGS,   %ecx
  rep    movsd

  mov    WORD * 9 (%eax),   %ecx
  push   %ecx
  popf
  mov    WORD * 6 (%eax),   %ebp
  mov    WORD * 5 (%eax),   %edi
  mov    WORD * 4 (%eax),   %esi
  mov    WORD * 3 (%eax),   %edx
  mov    WORD * 2 (%eax),   %ecx
  mov    WORD * 1 (%eax),   %ebx
  mov    (%eax),   %eax

  call   * WORD * (CONTEXT_ARGS + 3) (%esp)

  push   %eax
  mov    WORD * (CONTEXT_ARGS + 1) (%esp),   %eax
  mov    %ebx,   WORD * 1 (%eax)
  mov    %ecx,   WORD * 2 (%eax)
  mov    %edx,   WORD * 3 (%eax)
  mov    %esi,   WORD * 4 (%eax)
  mov    %edi,   WORD * 5 (%eax)
  mov    %ebp,   WORD * 6 (%eax)
  pushf
  pop    %ecx
  mov    %ecx,   WORD * 9 (%eax)
  pop    %ecx
  mov    %ecx,   (%eax)

  mov    %esp,   %esi
  mov    %eax,   %edi
  add    $WORD * CONTEXT_REGS,   %edi
  mov    $CONTEXT_ARGS,   %ecx
  rep    movsd
  add    $WORD * CONTEXT_ARGS,   %esp

  pop    %eax
  pop    %ebx
  pop    %ecx
  pop    %edx
  pop    %esi
  pop    %edi
  pop    %ebp
  ret


#else


  push   %r15
  push   %r14
  push   %r13
  push   %r12
  push   %r11
  push   %r10
  push   %r9
  push   %r8
  push   %rbp
  push   %rdi
  push   %rsi
  push   %rdx
  push   %rcx
  push   %rbx
  push   %rax

  sub    $WORD * CONTEXT_ARGS,   %rsp
  mov    %rdi,   %rsi
  mov    %rdi,   %rax
  add    $WORD * CONTEXT_REGS,   %rsi
  mov    %rsp,   %rdi
  mov    $CONTEXT_ARGS,   %rcx
  rep    movsq

  mov    WORD * 17 (%rax),   %r15
  mov    WORD * 16 (%rax),   %r14
  mov    WORD * 15 (%rax),   %r13
  mov    WORD * 14 (%rax),   %r12
  mov    WORD * 13 (%rax),   %r11
  mov    WORD * 12 (%rax),   %r10
  mov    WORD * 11 (%rax),   %r9
  mov    WORD * 10 (%rax),   %r8
  mov    WORD * 9 (%rax),    %rcx
  push   %rcx
  popf
  mov    WORD * 6 (%rax),   %rbp
  mov    WORD * 5 (%rax),   %rdi
  mov    WORD * 4 (%rax),   %rsi
  mov    WORD * 3 (%rax),   %rdx
  mov    WORD * 2 (%rax),   %rcx
  mov    WORD * 1 (%rax),   %rbx
  mov    (%rax),   %rax

  call   * WORD * (CONTEXT_ARGS + 4) (%rsp)

  push   %rax
  mov    WORD * (CONTEXT_ARGS + 1) (%rsp),   %rax
  mov    %rbx,   WORD * 1 (%rax)
  mov    %rcx,   WORD * 2 (%rax)
  mov    %rdx,   WORD * 3 (%rax)
  mov    %rsi,   WORD * 4 (%rax)
  mov    %rdi,   WORD * 5 (%rax)
  mov    %rbp,   WORD * 6 (%rax)
  pushf
  pop    %rcx
  mov    %rcx,   WORD * 9 (%rax)
  pop    %rcx
  mov    %rcx,   (%rax)
  mov    %r8,    WORD * 10 (%rax)
  mov    %r9,    WORD * 11 (%rax)
  mov    %r10,   WORD * 12 (%rax)
  mov    %r11,   WORD * 13 (%rax)
  mov    %r12,   WORD * 14 (%rax)
  mov    %r13,   WORD * 15 (%rax)
  mov    %r14,   WORD * 16 (%rax)
  mov    %r15,   WORD * 17 (%rax)

  mov    %rsp,   %rsi
  mov    %rax,   %rdi
  add    $WORD * CONTEXT_REGS,   %rdi
  mov    $CONTEXT_ARGS,   %rcx
  rep    movsq
  add    $WORD * CONTEXT_ARGS,   %rsp

  pop    %rax
  pop    %rbx
  pop    %rcx
  pop    %rdx
  pop    %rsi
  pop    %rdi
  pop    %rbp
  pop    %r8
  pop    %r9
  pop    %r10
  pop    %r11
  pop    %r12
  pop    %r13
  pop    %r14
  pop    %r15
  ret

#endif

