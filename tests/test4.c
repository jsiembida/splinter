
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int i, fd;
  char *file;
  sscanf(argv[1], " %d ", &i);
  file = argv[2];
  if (i < 1 || i > 1000000000 || !*file) return -1;
  while(i-->0) {
    fd = open(file, O_RDONLY);
    if (fd < 0) return -1;
    close(fd);
  }
  return 0;
}

