
/******************************************/

#include "splinter.h"
#define __USE_GNU
#define __USE_LARGEFILE64
#define __USE_XOPEN
#include <link-private.h>

/******************************************/


uint_t stats_memory_used = 0;


void * splinter_memory_alloc(uint_t size) {
  void * ptr;
  if (!size) return NULL;
  if ((ptr = calloc(1, size)) != NULL) {
    stats_memory_used += 1;
  } else {
    debug(DEBUG_ALL, "could not alloc %lu bytes", size);
  }
  return ptr;
}


void * splinter_memory_free(void *p) {
  if (p) {
    free(p);
    stats_memory_used -= 1;
  }
  return NULL;
}


int splinter_debug_level = 99;
int splinter_test_mode = 0;


static char socket_path[1024];
static uint_t socket_handle = -1;


static void __io_close() {
  DEBUG();

  if (socket_handle >= 0) {
    close(socket_handle);
    socket_handle = -1;
  }
}

static void __io_cleanup() {
  struct stat filestat;
  DEBUG();

  __io_close();
  if (socket_path[0]) {
    if (!stat(socket_path, &filestat)) {
      if (S_ISSOCK(filestat.st_mode)) {
        debug(DEBUG_ALL, "socket [%s] exists, deleting", socket_path);
        unlink(socket_path);
      }
    }
    bzero(socket_path, sizeof(socket_path));
  }
}

static char * __io_init() {
  int i, j;
  char * path_pattern;

  path_pattern = getenv("SPLINTER_SOCKET");
  if (!path_pattern) path_pattern = DEFAULT_SOCKET;

  for(i = j = 0; path_pattern[i];) {
    if (path_pattern[i] == '%') {
      switch(path_pattern[++i]) {
        case 0:
          break;
        case 'p': // Drop PID
          j += sprintf(socket_path + j, "%d", getpid());
          i++;
          break;
        case 'l': // Drop LOGIN
          j += sprintf(socket_path + j, "%s", getlogin());
          i++;
          break;
        default:
          socket_path[j++] = path_pattern[i++];
          break;
      }
    } else {
      socket_path[j++] = path_pattern[i++];
    }
  }
  socket_path[j] = 0;
  return socket_path;
}

static int __io_open(char * path) {
  int addr_len, fd;
  struct sockaddr_un addr;
  struct stat filestat;
  DEBUG();
  if (!stat(path, &filestat)) {
    if (S_ISSOCK(filestat.st_mode)) {
      DEBUG("socket [%s] exists, deleting", path);
      unlink(path);
    }
  }
  DEBUG("opening socket [%s]", path);
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) return -1;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  addr_len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;
  if (bind(fd, (struct sockaddr *)&addr, addr_len) || listen(fd, 1)) {
    close(fd);
    return -1;
  }
  return fd;
}

int __io_loop(char * path) {
  uint_t session_handle;
  int len;

  static char __in[IO_BUFF];
  static char __out[IO_BUFF];

  DEBUG();

  socket_handle = __io_open(path);
  if (socket_handle < 0) return -1;
  DEBUG("socket handle = %lu", socket_handle);

  while(1) {
    session_handle = accept(socket_handle, NULL, 0);
    if (session_handle < 0) break;

    while(1) {
      len = read(session_handle, __in, IO_BUFF - 1);
      if (len <= 0) break;
      len = splinter_handle_request(__in, len, __out, sizeof(__out));
      if (len <= 0) break;
      write(session_handle, __out, len);
    }
    close(session_handle);
  }

  close(socket_handle);
  socket_handle = -1;
  return 0;
}


static hook_p main_hook;
static uint_t elf_entry;
static struct link_map * main_handle = NULL;
static int child_pid = 0;

uint_t splinter_find_symbol(char * name) {
  if (!name) return 0;
  if (!main_handle) return 0;
  return (uint_t)dlsym(main_handle, name);
}

char * splinter_find_variable(char * name) {
  return NULL;
}

static pthread_t worker_thread;

void * worker(void * arg) {
  DEBUG("pid = %d", getpid());
  int err = __io_loop(socket_path);
  DEBUG("err = %d", err);
  while(1) sleep(1); // Just loop indifinietly
}

void do_fork() {
  DEBUG("pid = %d", getpid());
  __io_close();
  __io_init();
  ringbuf_reset();
  pthread_create(&worker_thread, NULL, worker, NULL);
}

extern int do_clone(int clone_flags, void *parent_code, void *child_code, void *child_stack, void *dx);

void do_parent(int pid) {
  DEBUG("pid = %d", getpid());
  atexit(__io_cleanup);
  pthread_atfork(NULL, NULL, do_fork);
  __io_init();
  // kill(child_pid = pid, SIGCONT);
  worker(NULL);
}

static uint_t __sp;
static uint_t __dx;

static void split() {
  int stack_size, args_size;
  void * stack_data;
  struct rlimit limits;

  DEBUG("pid = %d", getpid());

  main_hook->refcount = 0; // How bad is that??
  hook_uninstall(main_hook->id);
  main_hook = NULL;

  splinter_debug_level = 99;

  getrlimit(RLIMIT_STACK, &limits);
  stack_size = limits.rlim_cur;
  stack_data = malloc(stack_size);

  uint_t * stack = (uint_t *)__sp;
  for(stack++; *stack; stack++); // argc + args
  for(stack++; *stack; stack++); // NULL + env vars
  stack++;                       // terminal NULL
  args_size = ((void *)stack) - ((void *)__sp);
  memcpy(stack_data + stack_size - args_size, (void *)__sp, args_size);

  do_clone(CLONE_VM | CLONE_STOPPED | CLONE_THREAD | CLONE_SIGHAND | SIGCHLD, do_parent,
    (void *)elf_entry, stack_data + stack_size - args_size, (void *)__dx);
}

void _init() {
  char rule[256];

  if ((main_handle = dlopen("", RTLD_LAZY | RTLD_NOLOAD)) != NULL) {
    if (strings_init(STRING_BUFF)
      || atoms_init(MAX_ATOMS)
      || symbols_init(MAX_SYMBOLS)
      || ringbuf_init(128)
      || hooks_init(4, NULL, NULL))
      exit(-1);
    splinter_stats_dump();
    sleep(10);
    sprintf(rule, "{exec [mem %p [reg 3]] [mem %p [reg 7]] (call %p)}", &__dx, &__sp, split);
    elf_entry = (uint_t)main_handle->l_entry;
    main_hook = hook_install(elf_entry, rule, NULL, NULL, NULL, 0);
    main_hook->enabled = 1;
  } else {
    fprintf(stderr, "Cannot find ELF start code address, splinter gives up...\n");
  }
}

