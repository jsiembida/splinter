

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>


int main(int argc, char ** argv, char ** envp) {
  if (fork() == 0) exit(0);
  sleep(600);
}

