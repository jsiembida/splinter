
/********************************************************************/

#include "splinter.h"

/********************************************************************/

int splinter_debug_level = 0;
module_param(splinter_debug_level, int, 0);

static int splinter_buffer_size = 64;
module_param(splinter_buffer_size, int, 0);

static int splinter_max_hooks = 8;
module_param(splinter_max_hooks, int, 0);

int splinter_test_mode = 0;
module_param(splinter_test_mode, int, 0);

/* Now, that is gross! */
static unsigned long splinter_vmalloc_address = 0;
module_param(splinter_vmalloc_address, ulong, 0);
static unsigned long splinter_kallsyms_address = 0;
module_param(splinter_kallsyms_address, ulong, 0);

/********************************************************************/


static uint_t (*__kallsyms_callback) (char *) = NULL;

char * splinter_find_variable(char * name) {
  return NULL;
}

uint_t splinter_find_symbol(char * name) {
  DEBUG("looking up [%s]", name);

  if (!name || !*name) return 0;

  if (!__kallsyms_callback) {
    __kallsyms_callback = (uint_t (*)(char *))splinter_kallsyms_address;
  }

  if (__kallsyms_callback) {
    debug(DEBUG_DBG, "__kallsyms_callback = %p", __kallsyms_callback);
    return __kallsyms_callback(name);
  }
  debug(DEBUG_DBG, "__kallsyms_callback = NULL, no symbol lookup available");
  return 0;
}


/********************************************************************/


uint_t stats_memory_used = 0;


static void *(*__vmalloc_callback) (uint_t size) = NULL;


void * splinter_memory_alloc(uint_t size) {
  void *mem = NULL;

  if(!size) return mem;
  size = PAGE_ALIGN(size);

  if(!__vmalloc_callback)
    __vmalloc_callback = (void *(*)(uint_t))splinter_vmalloc_address;

  if(__vmalloc_callback) {
    mem = __vmalloc_callback(size);
  } else {
    mem = vmalloc(size);
  }

  if (mem) {
    DEBUG();
    memset(mem, 0, size);
    stats_memory_used += 1;
  } else {
    debug(DEBUG_ALL, "could not alloc %lu bytes", size);
  }
  return mem;
}


void * splinter_memory_free(void *mem) {
  if(mem) {
    DEBUG();
    vfree(mem);
    stats_memory_used -= 1;
  }
  return NULL;
}


/********************************************************************/

static void __hook_alloc_trigger(void) {
  try_module_get(THIS_MODULE);
}

static void __hook_free_trigger(void) {
  module_put(THIS_MODULE);
}

/********************************************************************/

static spinlock_t splinter_dev_lock;
static int splinter_dev_size = 32768;
static char * splinter_in_buff = NULL;
static char * splinter_out_buff = NULL;

static ssize_t splinter_dev_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
  int len, err;

  DEBUG("reading %u bytes", (unsigned)count);

  if (count > splinter_dev_size || count < 1024) {
    return -EIO;
  }

  err = copy_from_user(splinter_in_buff, buf, count);
  if (err) {
    return -EFAULT;
  }

  splinter_lock_get(splinter_dev_lock);
  len = splinter_handle_request(splinter_in_buff, count, splinter_out_buff, splinter_dev_size);
  splinter_lock_put(splinter_dev_lock);
  if (len <= 0) {
    return -EIO;
  }

  err = copy_to_user(buf, splinter_out_buff, len);
  if (err) {
    return -EFAULT;
  }

  *ppos += len;
  return len;
}

static ssize_t splinter_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
  DEBUG();
  return -EIO;
}

static int splinter_dev_open(struct inode *inode, struct file *file) {
  DEBUG();
  return 0;
}

static int splinter_dev_release(struct inode *inode, struct file *file) {
  DEBUG();
  return 0;
}

static const struct file_operations splinter_fops = {
  .owner        = THIS_MODULE,
  .read         = splinter_dev_read,
  .write        = splinter_dev_write,
  .open         = splinter_dev_open,
  .release      = splinter_dev_release,
};

/********************************************************************/

static int splinter_major_number = -1;
static struct class * splinter_class = NULL;
static struct device * splinter_device = NULL;


static int splinter_cleanup(void) {
  DEBUG();
  if (splinter_device) device_destroy(splinter_class, MKDEV(splinter_major_number, 0));
  if (splinter_class) class_destroy(splinter_class);
  if (splinter_major_number >= 0) unregister_chrdev(splinter_major_number, "splinter");
  splinter_memory_free(splinter_in_buff);
  splinter_memory_free(splinter_out_buff);
  hooks_cleanup();
  ringbuf_cleanup();
  symbols_cleanup();
  atoms_cleanup();
  strings_cleanup();
  return -ENODEV;
}


static int __init splinter_init(void)
{
  DEBUG();
  splinter_lock_init(splinter_dev_lock);

  if(splinter_debug_level < 0)
    splinter_debug_level = 0;
  if(splinter_debug_level > 99)
    splinter_debug_level = 99;

  if(splinter_max_hooks < 1)
    splinter_max_hooks = 1;
  if(splinter_max_hooks > 256)
    splinter_max_hooks = 256;

  splinter_test_mode = splinter_test_mode > 0;

  debug(DEBUG_ALL, "loading context_size = %d(%d) max_args = %d max_vars = %d "
                   "buffer_size = %d max_hooks = %d debug_level = %d test_mode = %d",
                   CONTEXT_BUFF, (int)sizeof(context_t), CONTEXT_ARGS, CONTEXT_VARS,
                   splinter_buffer_size, splinter_max_hooks,
                   splinter_debug_level, splinter_test_mode);

  if (strings_init(STRING_BUFF)
    || atoms_init(MAX_ATOMS)
    || symbols_init(MAX_SYMBOLS)
    || ringbuf_init(splinter_buffer_size)
    || hooks_init(splinter_max_hooks, __hook_alloc_trigger, __hook_free_trigger))
    return splinter_cleanup();

  if ((splinter_in_buff = splinter_memory_alloc(splinter_dev_size)) == NULL) {
    debug(DEBUG_ALL, "error allocating %d bytes for input buffer", splinter_dev_size);
    return splinter_cleanup();
  }

  if ((splinter_out_buff = splinter_memory_alloc(splinter_dev_size)) == NULL) {
    debug(DEBUG_ALL, "error allocating %d bytes for output buffer", splinter_dev_size);
    return splinter_cleanup();
  }

  if ((splinter_class = class_create(THIS_MODULE, "splinter")) == NULL) {
    debug(DEBUG_ALL, "error creating driver class");
    return splinter_cleanup();
  }

  if ((splinter_major_number = register_chrdev(0, "splinter", &splinter_fops)) < 0) {
    debug(DEBUG_ALL, "error registering character device");
    return splinter_cleanup();
  }

  if ((splinter_device = device_create(splinter_class, NULL, MKDEV(splinter_major_number, 0), NULL, "splinter")) == NULL) {
    debug(DEBUG_ALL, "error creating system device");
    return splinter_cleanup();
  }

  splinter_stats_dump();
  return 0;
}


static void __exit splinter_exit(void)
{
  debug(DEBUG_ALL, "unloading");
  splinter_cleanup();
  splinter_stats_dump();
}


module_init(splinter_init);
module_exit(splinter_exit);
MODULE_LICENSE("Dual BSD/GPL");
