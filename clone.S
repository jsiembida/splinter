
/*

  syscall number  %eax         call-clobbered
  arg 1           %ebx         call-saved
  arg 2           %ecx         call-clobbered
  arg 3           %edx         call-clobbered
  arg 4           %esi         call-saved
  arg 5           %edi         call-saved
  arg 6           %ebp         call-saved

  extern int do_clone(int clone_flags,
                      void *parent_code,
                      void *child_code,
                      void *child_stack,
                      void *dx);

*/

.text
.globl do_clone

do_clone:
  mov   $120, %eax
  mov   4(%esp), %ebx   // clone flags
  xor   %ecx, %ecx
  xor   %edx, %edx
  xor   %esi, %esi
  xor   %edi, %edi
  int   $0x80           // the old way

  orl   $0, %eax
  jz    child

parent:
  push  %eax
  xor   %ebp, %ebp
  push  %ebp
  jmp   *16(%esp)

child:
  mov   %esp, %eax
  mov   16(%eax), %esp
  mov   20(%eax), %edx
  jmp   *12(%eax)

