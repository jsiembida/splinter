

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>


void slepp(int secs) {
  struct timespec req;
  struct timespec rem;
  req.tv_sec = secs;
  req.tv_nsec = 0;
  while(nanosleep(&req, &rem)) {
    req.tv_sec = rem.tv_sec;
    req.tv_nsec = rem.tv_nsec;
  }
}

int main(int argc, char ** argv, char ** envp) {
  while(1) {
    fprintf(stderr, "Sleep...\n");
    slepp(1);
  }
  return 0;
}

