

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

void sig_handler(int arg, siginfo_t *info, void *data)
{
  int err;
  fprintf(stderr, "signal, signo=%d code=%d pid=%d\n", info->si_signo, info->si_code, info->si_pid);
  if (info->si_signo == SIGCHLD) wait(&err);
  else if (info->si_signo == SIGTERM) {
    fprintf(stderr, "terminate, pid=%d\n", getpid());
    exit(1);
  }
  // if (info->si_pid == child_pid && info->si_code == CLD_EXITED) exit(info->si_status);
}

int main(int argc, char ** argv, char ** envp) {
  int i, j;
  char buf[16];
  char * args[3];
  struct sigaction action;
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = sig_handler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGCHLD, &action, NULL);
  sigaction(SIGTERM, &action, NULL);

  srand(time(NULL));
  fprintf(stderr, "hello, pid=%d, argc=%d, argv0=[%s], argv1=[%s]\n", getpid(), argc, argv[0], argv[1]);

  while(1) {
    slepp(1);
    switch(rand() & 0xf) {
      case 0: // Fork...
        if (fork() == 0) {
          srand(getpid());
          fprintf(stderr, "fork, pid=%d\n", getpid());
        }
        break;
      case 1: // Exit...
        fprintf(stderr, "exit, pid=%d\n", getpid());
        exit(0);
      case 2:
      case 3: // Exec...
        j = 0;
        if (argc > 1) sscanf(argv[1], "%d", &j);
        sprintf(buf, "%d", ++j);
        args[0] = argv[0];
        args[1] = buf;
        args[2] = NULL;
        fprintf(stderr, "exec, argv0=[%s], argv1=[%s]\n", argv[0], buf);
        execve(argv[0], args, envp);
        break;
      default: // Do nothing by default...
        fprintf(stderr, "sleep, zzzz...\n");
        slepp(2 + (rand() % 5));
    }
  }
  return 0;
}

