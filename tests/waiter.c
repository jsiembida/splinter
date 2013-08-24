#include <unistd.h>
#include <stdio.h>

int main(int argc, char ** argv) {
  int i;
  if (fork()) {
    for(i = 0; i++ < 180;) {
      putc('.', stderr);
      if (i % 30 == 0)
        putc('\n', stderr);
      sleep(1);
    }
  }
  return 0;
}
