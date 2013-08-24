
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/syscall.h>

static int gimmeThatStuff() {
  return syscall(SYS_gettid);
}

static void handle_signal(int signum) {
  fprintf(stderr, "signal %i, pid %i, tid %i\n", signum, getpid(), gimmeThatStuff());
}

void * thread_loop(void * arg) {
  int i = *((int *)arg), j;
  for(j = 0; j < 100; j++) {
    fprintf(stderr, "%i: tick %04i, pid %i, tid %i\n", i, j, getpid(), gimmeThatStuff());
    sleep(3);
  }
  fprintf(stderr, "%i: exit, pid %i, tid %i\n", i, getpid(), gimmeThatStuff());
}

int main(int argc, char ** argv) {
  int args[5] = {0, 1, 2, 3, 4}, i;
  pthread_t threads[5];

  signal(1, handle_signal);
  signal(15, handle_signal);

  for(i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
    pthread_create(&threads[i], NULL, thread_loop, &args[i]);
    // fprintf(stderr, "%i: spawned thread %u\n", i, (unsigned int)threads[i]);
    sleep(1);
  }
  for(i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
    pthread_join(threads[i], NULL);
  }
  return 0;
}

