
.text
.globl atomic_swap

#ifdef __amd64__

atomic_swap:
  push %rbx
  push %rcx
  mov (%rdi), %ebx
  mov 4(%rdi), %ecx
  mov (%rsi), %eax
  mov 4(%rsi), %edx
  lock cmpxchg8b (%rsi)
  pop %rcx
  pop %rbx
  ret

#else

atomic_swap:
  push %edi
  push %ebx
  push %ecx
  mov (%eax), %ebx
  mov 4(%eax), %ecx
  mov %edx, %edi
  mov (%edi), %eax
  mov 4(%edi), %edx
  lock cmpxchg8b (%edi)
  pop %ecx
  pop %ebx
  pop %edi
  ret

#endif

