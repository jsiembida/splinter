#!/usr/bin/python

############################################################################

from re     import findall, finditer, match, search, sub
from os     import path, sysconf, environ, getlogin, listdir, spawnvp, P_WAIT
from sys    import stdout, stdin, stderr, argv, exit
from socket import socket, AF_UNIX, SOCK_STREAM
from ctypes import cdll, create_string_buffer

############################################################################

def isLoaded():
   return path.exists('/dev/splinter')

def exitIfNotLoaded():
   if not isLoaded():
      print '\nSplinter kernel module not loaded...\n'
      exit(-1)

############################################################################

symbolFile = environ.get('SPLINTER_SYMBOLS', '/proc/kallsyms')
symbolCache = {}

def findAddress(symbol, ignoreExceptions = True):
   try:
      if not symbolCache:
         f = open(symbolFile)
         for (a, t, s) in (l.strip().split()[0:3] for l in f):
            symbolCache[s] = a
         f.close()
      return symbolCache[symbol.strip()]
   except Exception, e:
      if ignoreExceptions:
         return ''
      raise e

############################################################################

def netstringSet(*vals):
   return ''.join([str(len(str(v))) + ':' + str(v) + ',' for v in vals])

def netstringGet(string):
   try:
      (l, d) = string.split(':', 1)
      if (not d) or (len(l) > 6):
         raise Exception
      l = int(l)
   except:
      return None, None
   return (d[:l], d[(l + 1):]) if d[l] is ',' else (None, None)

def netstringUnroll(string):
   values = []
   while string:
      v, string = netstringGet(string)
      if v:
         values.append(v)
   return values

############################################################################

class InterfaceException(Exception):
   pass

############################################################################

class DirectoryInterface(object):
   def __init__(self, dir = '.'):
      if dir[-1] != '/':
         dir += '/'
      if not path.isdir(dir):
         raise InterfaceException('Directory ' + dir + ' does not exist')
      self.dir = dir

   def read(self, name, ignoreNonExistent = True):
      try:
         f = open(self.dir + '/' + name)
      except IOError, e:
         if ignoreNonExistent:
            return ''
         raise e
      l = f.read()
      f.close()
      return l

   def write(self, name, value):
      if not (hasattr(value, 'iter') or hasattr(value, '__iter__')):
         value = [value]
      f = open(self.dir + '/' + name, 'w')
      f.writelines(map(str, value))
      f.close()
      return None

############################################################################

class DeviceInterface(object):
   """
   This cannot be done as a regular file access.
   Kernel module writes data IN PLACE, in a buffer
   provided upon request.
   """
   def __init__(self, path = '/dev/splinter'):
      self.libc = cdll.LoadLibrary("libc.so.6")
      self.fd = self.libc.open(path, 0)
      if self.fd < 0:
         raise InterfaceException('Device ' + path + ' could not be opened')

   def close(self):
      if self.fd >= 0:
         self.libc.close(self.fd)
      self.fd = -1

   def msg(self, msg):
      # stderr.write('dev snd = [' + str(msg) + ']\n')
      msg_buf = create_string_buffer(msg, 16 * 1024)
      if self.libc.read(self.fd, msg_buf, len(msg_buf)) <= 0:
         return None
      # stderr.write('dev rcv = [' + str(msg_buf.value) + ']\n')
      return msg_buf.value

############################################################################

class SocketInterface(object):
   def __init__(self, path = None):
      self.fd = socket(AF_UNIX, SOCK_STREAM)
      if self.fd < 0:
         raise InterfaceException('Socket ' + path + ' could not be opened')
      self.fd.connect(path)

   def close(self):
      if self.fd >= 0:
         fd.close()
      self.fd = -1

   def msg(self, msg):
      self.fd.send(msg)
      reply = self.fd.recv(16 * 1024)
      return None if not reply else reply

############################################################################

def getDefaultInterface():
   vals = globals()
   if vals.has_key('defaultInterface'):
      return vals['defaultInterface']
   if environ.has_key('SPLINTER_PID'):
      p = environ.get('SPLINTER_SOCKET', "/var/run/.%l-splinter.%p")
      p = p.replace('%p', environ['SPLINTER_PID']).replace('%l', getlogin())
      print p
      vals['defaultInterface'] = SocketInterface(p)
   else:
      exitIfNotLoaded()
      vals['defaultInterface'] = DeviceInterface()
   return vals['defaultInterface']

############################################################################

class HookException(Exception):
   pass

class Hook(object):
   def __init__(self, num, interface = None):
      if not interface:
         interface = getDefaultInterface()
      self.interface, self.num, self.text = interface, num, ''
      self.stats()

   def msg(self, req, *values):
      request = netstringSet('SPLINTER_' + req + '_REQ', self.num, *values)
      reply = self.interface.msg(request)
      vals = netstringUnroll(reply)
      if (len(vals) < 2) or (vals[0] != 'SPLINTER_' + req + '_ANS'):
         raise Exception('Incorrect reply: ' + reply)
      if int(vals[1]) != int(self.num):
         raise HookException(vals[2] if vals[2] else "Unknown error")
      vals = vals[2:]
      self.enable, self.refcount, self.address, self.hits, self.dropped, self.text, self.store = \
         map(int, vals[:5]) + [str(vals[5]), map(int, vals[6:])]

   def stats(self):
      self.msg('STAT')

   def enabled(self, flag):
      self.msg('ENAB', 1) if flag else self.msg('ENAB', 0)

   def zero(self):
      self.msg('ZERO')

   def unhook(self):
      if self.isHooked():
         self.msg('UNHO')
         if self.isHooked():
            raise HookException('Unhooking ' + self.text + ' failed')

   def isHooked(self):
      return self.address != 0

   def values(self):
      val = {'num':self.num, 'address':'%x'%self.address, 'hits':self.hits, 'dropped':self.dropped, \
         'text':self.text, 'refcount':self.refcount, 'enable': 'on' if self.enable else 'off'}
      for i, v in enumerate(self.store):
        val['store' + str(i)] = v
      return val

   def __eq__(self, other):
      return self.num == other.num

   def __ne__(self, other):
      return self.num != other.num

############################################################################

class Rule(DirectoryInterface):
   _escapeChar = '%'
   _maxVars = 8
   _vars = {}

   _regs_x16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip', 'flags']
   _regs_x32 = map(lambda r: 'e'+r, _regs_x16)
   _regs_x64 = map(lambda r: 'r'+r, _regs_x16) + map(lambda r: 'r'+str(r), range(8, 16))

   _args_x32_cdecl  = map(lambda a: 'arg '+str(a), range(10))
   _args_x32_reg1   = ['eax'] + _args_x32_cdecl[:-1]
   _args_x32_reg2   = ['eax', 'edx'] + _args_x32_cdecl[:-2]
   _args_x32_reg3   = ['eax', 'edx', 'ecx'] + _args_x32_cdecl[:-3]
   _args_x32_kernel = _args_x32_reg3
   _args_x64        = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'arg 0', 'arg 1', 'arg 2', 'arg 3']

   def __replaceRets(self, l):
      return l.replace(self._escapeChar + 'ret', 'reg 0')

   def __replaceEols(self, l):
      return l.replace(self._escapeChar + 'eol', 'print-char 10')

   def __replaceWords(self, l):
      return l.replace(self._escapeChar + 'word', '8' if self.is64bit else '4')

   def __replaceRegs(self, l, r):
      for i, n in enumerate(r):
         l = l.replace(self._escapeChar + n, 'reg ' + str(i))
      return l

   def __replaceArgs(self, l, a):
      for i, n in enumerate(a):
         if n.startswith('arg ') or n.startswith('reg ') or n.startswith('mem '):
            l = l.replace(self._escapeChar + 'arg' + str(i), n)
         else:
            l = l.replace(self._escapeChar + 'arg' + str(i), self._escapeChar + n)
      return l

   def __replaceVars(self, l):
      for v in findall('\\' + self._escapeChar + '[_a-zA-Z][_a-zA-Z0-9]*', l):
         if v not in self._vars:
            if len(self._vars) > self._maxVars:
               raise Exception('\n\nSorry Dude, too many variables...\n')
            self._vars[v] = 'var ' + str(len(self._vars))
         l = l.replace(v, self._vars[v])
      return l

   def __replaceEnvs(self, l, removeIfNotFound = True):
      for e in findall('\$[_a-zA-Z][_a-zA-Z0-9]*', l):
         e = e[1:]
         if e in environ:
            l = l.replace('$' + e, environ[e])
         else:
            if removeIfNotFound:
               l = l.replace('$' + e, '')
      return l

   def __replaceSymbols(self, l):
      for s in findall('\@[_a-zA-Z][_a-zA-Z0-9]*', l):
         addr = findAddress(s[1:])
         if addr:
            l = l.replace(s, '0x' + addr)
      return l

   def __replaceLine(self, l, args, regs, shift = 0):
      if match('^\s*\#', l):
         return ''
      l = self.__replaceEnvs(l, False)
      l = self.__replaceRets(l)
      l = self.__replaceEols(l)
      l = self.__replaceWords(l)
      l = self.__replaceArgs(l, args[shift:])
      l = self.__replaceRegs(l, regs)
      l = self.__replaceVars(l)
      l = self.__replaceSymbols(l)
      l = self.__replaceEnvs(l)
      return l

   def __replaceText(self, s, args, regs, shift):
      return '\n'.join([self.__replaceLine(l, args, regs, shift) for l in s.splitlines()])

   def __parseOptions(self, options):
      (arch, conv, shift) = (None, '_cdecl', 0)
      for arg in options:
         if arg in ('cdecl', 'kernel', 'reg1', 'reg2', 'reg3'):
            conv = '_' + arg
         elif arg in ('x32', 'x64'):
            arch = '_' + arg
         elif arg == 'shift':
            shift = 1
      if not arch:
         arch = '_x32'
         if self.is64bit:
            arch = '_x64'
            conv = ''
      return (getattr(self, '_args' + arch + conv), getattr(self, '_regs' + arch), shift)

   def __init__(self, dir, text = ''):
      super(Rule, self).__init__(dir)
      self.is64bit = (sysconf('SC_LONG_BIT') == 64)
      self.address = self.read('address').strip()
      if self.address != '0':
         address = findAddress(self.address)
         if address:
            self.address = address
      self.text = self.read('text')
      if not self.text:
         self.text = text
      self.options = self.read('options')
      if not self.options:
         self.options = 'kernel'
      (args, regs, shift) = self.__parseOptions(self.options.split())
      self.entry = self.__replaceText(self.read('entry'), args, regs, shift)
      self.exit = self.__replaceText(self.read('exit'), args, regs, shift)
      if (not self.address) and (not self.entry) and (not self.exit):
         raise InterfaceException('Directory ' + self.dir + ' does not contain a proper structure')

   def values(self):
      val = {'dir':self.dir, 'address':self.address, 'entry':self.entry, 'exit':self.exit, 'options':self.options, 'text':self.text}
      return val

############################################################################

rulesetCache = {}
hookCache = {'filled': False, 'last': 0}

def __readHook(num):
   if (not hookCache.has_key(num)) and (not hookCache['filled']):
      if num < hookCache['last']:
         return None
      try:
         hookCache[num] = Hook(num)
         hookCache['last'] = num
      except HookException:
         hookCache['filled'] = True
   return hookCache[num] if hookCache.has_key(num) else None

def __readHooks(filters = '', addFreeHooks = False):
   if not filters:
      filters = ['']
   if not (hasattr(filters, 'iter') or hasattr(filters, '__iter__')):
      filters = [filters]
   ret, hooks = [], [h for h in [__readHook(i) for i in range(1, 256)] if h]
   for f in filters:
      f, cur = str(f).strip().lower(), []
      if not f and not addFreeHooks:
         cur = hooks
      if f and not cur:
         cur += [h for h in hooks if search(f, h.text.strip().lower())]
      if f and not cur:
         try:
            h = __readHook(int(f))
            if h:
               cur.append(h)
         except Exception, e:
            pass
      if addFreeHooks:
         cur += [h for h in hooks if not h.isHooked()]
      ret += [h for h in cur if h not in ret]
   return ret

def do_help(args):
   for k, v in sorted(((k, v) for k, v in globals().items() if k.startswith('do_') and k != 'do_help' and callable(v))):
      print k[3:].replace('_', '-') + ':\n' + str(v.__doc__)

def do_hook_show(args):
   """
   Show all loaded hooks meeting the given search criteria. If no search phrase
   is given, all hooks are shown. As a search query a fragment of text assigned
   to a hook, regex or hook numbers or their hexadecimal addresses can be used.
   If defined, SPLINTER_FORMAT is used to format the output of this command in
   accordance to standard python string formatting rules. By default it is:
   '%(num)3s %(address)17s %(enable)8s %(refcount)4s %(hits)8s %(dropped)8s   %(text)s'

   Examples:
      splinter hook-show
      splinter hook-show connect open
      splinter hook-show 4 5 6
      splinter hook-show connect file/close '^file/[abcd]'
      splinter hook-show 1 2 3 '^file/' c10b13a3
      SPLINTER_FORMAT='%(num)s %(address)s %(enable)s %(hits)s %(dropped)s %(text)s' splinter hook-show
   """
   if environ.has_key('SPLINTER_FORMAT'):
      fmt = environ['SPLINTER_FORMAT']
   else:
      fmt = '%(num)3s %(address)17s %(enable)8s %(refcount)4s %(hits)8s %(dropped)8s   %(text)s'
      print fmt % {'num':'', 'address':'address', 'enable':'on/off', 'refcount':'ref', 'hits':'hits', 'dropped':'dropped', 'text':'notes'}
   for h in __readHooks(args):
      print fmt % h.values()

def __do_rules(callback, args):
   for arg in [a for a in args if a]:
      paths = [arg]
      if environ.has_key('SPLINTER_DIR'):
         paths.append(environ['SPLINTER_DIR'] + '/' + arg)
      for p in paths:
         if path.isdir(p):
            callback(p, arg)
            break

def __do_shot_load(p, arg):
   try:
      r = Rule(p)
      interface = getDefaultInterface()
      reply = interface.msg(netstringSet('SPLINTER_SHOT_REQ', r.entry))
   except InterfaceException:
      pass

def do_shot_load(args):
   """
   Loads and executes a 'one-time' shot. Takes names of rulesets defining
   actions taken by shots. SPLINTER_DIR variable is used as in hook loading.

   Examples:
      splinter shot-load shot/fd-close
      splinter shot-load shot/zombie-kill
   """
   exitIfNotLoaded()
   __do_rules(__do_shot_load, args)

def __do_hook_load(p, arg):
   try:
      r = Rule(p, arg)
      request = netstringSet('SPLINTER_HOOK_REQ', r.address, r.entry, r.exit, r.text)
      reply = getDefaultInterface().msg(request)
      vals = netstringUnroll(reply)
      if (len(vals) < 3) or (vals[0] != 'SPLINTER_HOOK_ANS'):
         raise HookException('incorrect reply: ' + reply)
      if int(vals[1]) == 0:
         raise HookException(str(vals[2]))
      print 'Success:', r.text, '@', r.address
   except HookException, e:
      print 'Failure:', r.text, '@', r.address, '[' + str(e) + ']'
   except InterfaceException, e:
      for p, a in [(p + '/' + x, arg + '/' + x) for x in listdir(p) if path.isdir(p + '/' + x)]:
         __do_hook_load(p, a)

def do_hook_load(args):
   """
   Installs hooks from given rule(s). Arguments are interpreted as paths looked
   up for rules. If a path found is a directory containing subdirs instead of
   a rule definition, a recursive look-up is done. If no path with a rule is
   found, SPLINTER_DIR if defined is used as a root directory for rules and the
   look-up is repeated. Preprocessing is performed before rule is loaded into
   memory, see rule-show to find out more.

   Examples:
      splinter hook-load proc/kill net/connect io
      splinter hook-load proc net/connect io
      SPLINTER_DIR=/usr/share/splinter.d splinter hook-load file proc io
   """
   exitIfNotLoaded()
   __do_rules(__do_hook_load, args)

def do_hook_unload(args):
   """
   Unloads from memory hooks meeting given criteria (see hook-show for more on
   how to select hooks). This effectively brings hooked code to its original
   state and frees a slot in splinter for a hook to be loaded.

   Examples:
      splinter hook-unload
      splinter hook-unload proc/
      splinter hook-unload 1 2 net/
   """
   for h in __readHooks(args):
      h.unhook()

def do_hook_zero(args):
   """
   Zeros counters for loaded hooks meeting given search criteria. See hook-show
   for more about how to select hooks. This operation is unrelated to enabling
   or disabling a hook.

   Examples:
      splinter hook-zero file/open file/close
   """
   exitIfNotLoaded()
   for h in __readHooks(args):
      h.zero()

def do_hook_enable(args):
   """
   Enables loaded hooks meeting given search criteria. See hook-show for more
   about how to select hooks. By default, a hook is enabled when loaded.

   Examples:
      splinter hook-enable file/open file/close
   """
   for h in __readHooks(args):
      h.enabled(True)

def do_hook_disable(args):
   """
   Disables loaded hooks meeting given search criteria. See hook-show for
   more about how to select hooks. When disabled, a hook remains in memory
   it is not executed though, neither are updated its counters.

   Examples:
      splinter hook-disable file/open file/close
   """
   for h in __readHooks(args):
      h.enabled(False)

def __do_rule_show(p, arg):
   try:
      r = Rule(p, arg)
      v = r.values()
      fmt = '### path: %(dir)s\n'
      if hasattr(v, 'text'):
         fmt += '### text: %(text)s\n'
      fmt += '### address: %(address)s\n### options: %(options)s\n### entry:\n%(entry)s\n### exit:\n%(exit)s\n'
      print fmt % v
   except InterfaceException, e:
      for p, a in [(p + '/' + x, arg + '/' + x) for x in listdir(p) if path.isdir(p + '/' + x)]:
         __do_rule_show(p, a)

def do_rule_show(args):
   """
   Shows a rule as it is passed along while loading a hook after having been
   preprocessed. See hook-load to find out more on how rule look-up is done.

   Examples:
      splinter rule-show proc/kill net/connect
      SPLINTER_DIR=/usr/share/splinter.d splinter rule-show file proc
   """
   __do_rules(__do_rule_show, args)

def do_stats_show(args):
   """
   Shows splinter's internal memory usage statistics.

   Examples:
      splinter stats-show
   """
   seq = 123
   reply = getDefaultInterface().msg(netstringSet('SPLINTER_PING_REQ', seq))
   vals = netstringUnroll(reply)
   if (len(vals) < 2) or (vals[0] != 'SPLINTER_PING_ANS'):
      raise Exception('Incorrect reply: ' + reply)
   if int(vals[1]) != int(seq):
      raise HookException('Incorrect ping reply: ' + reply)
   s = map(lambda (i,s): '\n'+s+': '+vals[i] if s else '', enumerate(
      ('Version', '\nContext size', 'Context args', 'Context vars', 'Context store', '\nMemory chunks used',
      '\nStrings total bytes', 'Strings free bytes', 'Strings used', 'Strings used bytes',
      '\nAtoms total', 'Atoms total bytes', 'Atoms free', 'Atoms free bytes', 'Atoms used', 'Atoms used bytes',
      '\nHooks total', 'Hooks total bytes', 'Hooks free', 'Hooks free bytes',
      'Hooks used', 'Hooks used bytes', 'Hooks limbo', 'Hooks limbo bytes',
      '\nSymbols total', 'Symbols total bytes', 'Symbols free',
      'Symbols free bytes', 'Symbols used', 'Symbols used bytes',
      '\nRingbuf size', 'Ringbuf fill', 'Ringbuf head', 'Ringbuf drops'), 2))
   print ''.join(s)

def do_module_load(args):
   """
   Loads a splinter kernel module with neccessary parameters, also provides
   couple of convenience shorthands; debug, test, huge, big, small, profiler.
   Upon its load splinter module leaves info in system logs, the debug option
   increases its verbosity. Small, big and huge options determine the number
   of slots splinter will use, issue 'splinter hook-show' afterwards.

   Examples:
      splinter module-load debug
      splinter module-load small
      splinter module-load huge debug
   """
   if isLoaded():
      print '\nSplinter already loaded...\n'
      exit(-1)

   moduleOptions = {'splinter_debug_level':0, 'splinter_max_hooks':16, 'splinter_buffer_size':250000}

   moduleOptions['splinter_vmalloc_address'] = findAddress('module_alloc')
   if not moduleOptions['splinter_vmalloc_address']:
      print "Couldn't determine module_alloc address from " + symbolFile + ", quitting"
      exit(-1)
   moduleOptions['splinter_vmalloc_address'] = '0x' + moduleOptions['splinter_vmalloc_address']

   moduleOptions['splinter_kallsyms_address'] = findAddress('kallsyms_lookup_name')
   if not moduleOptions['splinter_kallsyms_address']:
      print "Couldn't determine kallsyms_lookup_name address from " + symbolFile + ", quitting"
      exit(-1)
   moduleOptions['splinter_kallsyms_address'] = '0x' + moduleOptions['splinter_kallsyms_address']

   for arg in args:
      arg = sub('[^a-zA-Z0-9]', ' ', arg.lower().strip())
      if 'debug' in arg:
         moduleOptions['splinter_debug_level'] = 9
      elif 'profiler' in arg:
         moduleOptions['splinter_max_hooks'] = 256
         moduleOptions['splinter_buffer_size'] = 100000
      elif 'huge' in arg:
         moduleOptions['splinter_max_hooks'] = 128
         moduleOptions['splinter_buffer_size'] = 4000000
      elif 'big' in arg:
         moduleOptions['splinter_max_hooks'] = 32
         moduleOptions['splinter_buffer_size'] = 1000000
      elif 'small' in arg:
         moduleOptions['splinter_max_hooks'] = 4
         moduleOptions['splinter_buffer_size'] = 10000
      elif 'test' in arg:
          moduleOptions['splinter_test_mode'] = 1

   args = ['modprobe', 'splinter'] + map(lambda (k,v): k+'='+str(v), moduleOptions.items())
   exit(spawnvp(P_WAIT, 'modprobe', args))

def do_module_unload(args):
   """
   Unloads the kernel splinter module. Upon which all hooks are unloaded too.

   Examples:
      splinter module-unload
   """
   if not isLoaded():
      print '\nSplinter not loaded...\n'
      exit(-1)
   exit(spawnvp(P_WAIT, 'rmmod', ['rmmod', 'splinter']))

def do_buffer_show(args):
   """
   Shows the content of a memory buffer. The buffer is a ring buffer, when
   overflown, dropped bytes counter is updated accordingly. Also by design,
   once read from buffer data is discarded, which immitates 'dmesg -c'.

   Examples:
      splinter buffer-show
   """
   interface, dropped = getDefaultInterface(), 0
   while True:
      reply = interface.msg(netstringSet('SPLINTER_DUMP_REQ'))
      vals = netstringUnroll(reply)
      if (len(vals) != 3) or (vals[0] != 'SPLINTER_DUMP_ANS'):
         break
      dropped += int(vals[1]) # what to do with this?
      stdout.write(vals[2])
      # This is a protection not an optimization
      if len(vals[2]) < 4096:
         break

############################################################################

args = argv[1:]
if not args:
   args = ('help')

call = args[0].replace('-', '_')
args = args[1:]

if globals().has_key('do_' + call):
   call = globals()['do_' + call]
else:
   call = None

if not callable(call):
   call = globals()['do_help']

call(args)

############################################################################
