#!/usr/bin/env python

############################################################################

from re     import findall, finditer, match, search, sub
from os     import path, sysconf, environ, getlogin, listdir, spawnvp, P_WAIT
from sys    import stdout, stdin, stderr, argv, exit
from socket import socket, AF_UNIX, SOCK_STREAM
from ctypes import cdll, create_string_buffer

############################################################################

deviceFile = environ.get('SPLINTER_DEVICE', '/dev/splinter')

def isModuleLoaded():
   return path.exists(deviceFile)

def exitIfModuleNotLoaded():
   if not isModuleLoaded():
      print('\nSplinter kernel module not loaded...\n')
      exit(-1)

############################################################################

symbolFile = environ.get('SPLINTER_SYMBOLS', '/proc/kallsyms')
symbolCache = {}

def findAddress(symbol, ignoreExceptions = True):
   try:
      if not symbolCache:
         with open(symbolFile) as f:
            for (addr, addr_type, sym) in (l.strip().split()[0:3] for l in f):
               symbolCache[sym] = addr
      return symbolCache[symbol.strip()]
   except Exception as e:
      if not ignoreExceptions:
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
      return (d[:l], d[(l + 1):]) if d[l] is ',' else (None, None)
   except:
      pass
   return (None, None)

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
   def __init__(self, dir = path.curdir):
      if dir[-1] != path.sep:
         dir += path.sep
      if not path.isdir(dir):
         raise InterfaceException('Directory ' + dir + ' does not exist')
      self.dir = dir

   def read(self, name, ignoreNonExistent = True):
      try:
         f = open(self.dir + path.sep + name)
      except IOError as e:
         if ignoreNonExistent:
            return None
         raise e
      l = f.read()
      f.close()
      return l

   def write(self, name, value):
      if not (hasattr(value, 'iter') or hasattr(value, '__iter__')):
         value = [value]
      with open(self.dir + path.sep + name, 'w') as f:
         f.writelines(map(str, value))
      return None

############################################################################

class DeviceInterface(object):
   """
   This cannot be done as a regular file access.
   Kernel module writes data IN PLACE, in a buffer
   provided upon request.
   """
   def __init__(self, path = deviceFile):
      self.libc = cdll.LoadLibrary("libc.so.6")
      self.fd = self.libc.open(path, 0)
      if self.fd < 0:
         raise InterfaceException('Device ' + path + ' could not be opened')

   def close(self):
      if self.fd >= 0:
         self.libc.close(self.fd)
      self.fd = -1

   def msg(self, msg_data):
      # stderr.write('dev snd = [' + str(msg_data) + ']\n')
      max_len = 16 * 1024
      msg_padded = msg_data + ('\x00' * (max_len - len(msg_data) - 1))
      msg_buf = create_string_buffer(msg_padded)
      if self.libc.read(self.fd, msg_buf, len(msg_buf)) <= 0:
         return None
      # stderr.write('dev rcv = [' + str(msg_buf.value) + ']\n')
      return msg_buf.value

############################################################################

class SocketInterface(object):
   def __init__(self, path):
      self.fd = socket(AF_UNIX, SOCK_STREAM)
      if self.fd < 0:
         raise InterfaceException('Socket ' + path + ' could not be opened')
      self.fd.connect(path)

   def close(self):
      if self.fd >= 0:
         fd.close()
      self.fd = -1

   def msg(self, msg):
      max_len = 16 * 1024
      self.fd.send(msg)
      reply = self.fd.recv(max_len)
      return None if not reply else reply

############################################################################

def getDefaultInterface():
   vals = globals()
   if 'defaultInterface' not in vals:
      if 'SPLINTER_PID' in environ:
         p = environ.get('SPLINTER_SOCKET', "/var/run/.%l-splinter.%p")
         p = p.replace('%p', environ['SPLINTER_PID']).replace('%l', getlogin())
         vals['defaultInterface'] = SocketInterface(p)
      else:
         exitIfModuleNotLoaded()
         vals['defaultInterface'] = DeviceInterface()
   return vals['defaultInterface']

############################################################################

class HookException(Exception):
   pass

class Hook(object):
   def __init__(self, num, interface = None):
      self.interface = interface if interface else getDefaultInterface()
      self.num, self.text = num, ''
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

class RuleException(Exception):
   pass

class Rule(DirectoryInterface):
   _escapeChar = '%'
   _maxVars = 8
   _vars = {}

   _regs_x16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip', 'flags']
   _regs_x32 = list(map(lambda r: 'e'+r, _regs_x16))
   _regs_x64 = list(map(lambda r: 'r'+r, _regs_x16)) + list(map(lambda r: 'r'+str(r), range(8, 16)))

   _args_x32_cdecl  = list(map(lambda a: 'arg '+str(a), range(10)))
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
      for v in findall('\\*[_a-zA-Z][_a-zA-Z0-9]*', l):
         if v not in self._vars:
            self._vars[v] = 'var ' + str(len(self._vars))
            if len(self._vars) > self._maxVars:
               raise RuleException('Too many variables in the rule (' + str(self._maxVars) + ' allowed)')
         l = l.replace(v, self._vars[v])
      return l

   def __replaceEnvs(self, l, removeIfNotFound = True):
      for e in findall('\$[_a-zA-Z][_a-zA-Z0-9]*', l):
         e = e[1:]
         if e in environ:
            l = l.replace('$' + e, environ[e])
         else:
            raise RuleException('Unknown environment variable: ' + e)
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
      l = self.__replaceEnvs(l)
      l = self.__replaceRets(l)
      l = self.__replaceEols(l)
      l = self.__replaceWords(l)
      l = self.__replaceArgs(l, args[shift:])
      l = self.__replaceRegs(l, regs)
      l = self.__replaceVars(l)
      l = self.__replaceSymbols(l)
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
         else:
            raise RuleException('Unknown option: ' + e)
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
   if (not num in hookCache) and (not hookCache['filled']):
      if num < hookCache['last']:
         return None
      try:
         hookCache[num] = Hook(num)
         hookCache['last'] = num
      except HookException:
         hookCache['filled'] = True
   return hookCache[num] if (num in hookCache) else None

def __readHooks(filters = '', addFreeHooks = False):
   if not filters:
      filters = ['']
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
         except Exception as e:
            pass
      if addFreeHooks:
         cur += [h for h in hooks if not h.isHooked()]
      ret += [h for h in cur if h not in ret]
   return ret

def do_help(args):
   for k, v in sorted(((k, v) for k, v in globals().items() if k.startswith('do_') and k != 'do_help')):
      print(k[3:].replace('_', '-') + ':\n' + str(v.__doc__))

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
   if 'SPLINTER_FORMAT' in environ:
      fmt = environ['SPLINTER_FORMAT']
   else:
      fmt = '%(num)3s %(address)17s %(enable)8s %(refcount)4s %(hits)8s %(dropped)8s   %(text)s'
      print(fmt % {'num':'', 'address':'address', 'enable':'on/off', 'refcount':'ref', 'hits':'hits', 'dropped':'dropped', 'text':'notes'})
   for h in __readHooks(args):
      print(fmt % h.values())

def __do_rules(callback, args):
   for arg in [a for a in args if a]:
      paths = [arg]
      if 'SPLINTER_DIR' in environ:
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
   exitIfModuleNotLoaded()
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
      print('Success:', r.text, '@', r.address)
   except HookException as e:
      print('Failure:', r.text, '@', r.address, '[' + str(e) + ']')
   except InterfaceException as e:
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
   exitIfModuleNotLoaded()
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
   exitIfModuleNotLoaded()
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
      print(fmt % v)
   except InterfaceException as e:
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
   s = map(lambda x: '\n'+x[1]+': '+vals[x[0]], enumerate(
      ('Version', '\nContext size', 'Context args', 'Context vars', 'Context store', '\nMemory chunks used',
      '\nStrings total bytes', 'Strings free bytes', 'Strings used', 'Strings used bytes',
      '\nAtoms total', 'Atoms total bytes', 'Atoms free', 'Atoms free bytes', 'Atoms used', 'Atoms used bytes',
      '\nHooks total', 'Hooks total bytes', 'Hooks free', 'Hooks free bytes',
      'Hooks used', 'Hooks used bytes', 'Hooks limbo', 'Hooks limbo bytes',
      '\nSymbols total', 'Symbols total bytes', 'Symbols free',
      'Symbols free bytes', 'Symbols used', 'Symbols used bytes',
      '\nRingbuf size', 'Ringbuf fill', 'Ringbuf head', 'Ringbuf drops'), 2))
   print(''.join(s))

def do_module_load(args):
   """
   Loads a splinter kernel module with necessary parameters, also provides
   couple of convenience shorthands; debug, test, huge, big, small, profiler.
   Once loaded, splinter module leaves info in system logs, the debug option
   increases verbosity. Small, big and huge options determine the number of
   slots splinter will use, you may wanna issue 'splinter hook-show' afterwards.

   Examples:
      splinter module-load debug
      splinter module-load small
      splinter module-load huge debug
   """
   if isModuleLoaded():
      print('\nSplinter already loaded...\n')
      exit(-1)

   moduleOptions = {'splinter_debug_level':      0,
                    'splinter_max_hooks':        16,
                    'splinter_buffer_size':      250000,
                    'splinter_vmalloc_address':  findAddress('module_alloc'),
                    'splinter_kallsyms_address': findAddress('kallsyms_lookup_name')}

   if not moduleOptions['splinter_vmalloc_address']:
      print("Couldn't determine module_alloc address from " + symbolFile + ", quitting")
      exit(-1)
   moduleOptions['splinter_vmalloc_address'] = '0x' + moduleOptions['splinter_vmalloc_address']

   if not moduleOptions['splinter_kallsyms_address']:
      print("Couldn't determine kallsyms_lookup_name address from " + symbolFile + ", quitting")
      exit(-1)
   moduleOptions['splinter_kallsyms_address'] = '0x' + moduleOptions['splinter_kallsyms_address']

   for arg in args:
      if arg == 'debug':
         moduleOptions['splinter_debug_level'] = 9
      elif arg == 'profiler':
         moduleOptions['splinter_max_hooks'] = 256
         moduleOptions['splinter_buffer_size'] = 100000
      elif arg == 'huge':
         moduleOptions['splinter_max_hooks'] = 128
         moduleOptions['splinter_buffer_size'] = 4000000
      elif arg == 'big':
         moduleOptions['splinter_max_hooks'] = 32
         moduleOptions['splinter_buffer_size'] = 1000000
      elif arg == 'small':
         moduleOptions['splinter_max_hooks'] = 4
         moduleOptions['splinter_buffer_size'] = 10000
      elif arg == 'test':
         moduleOptions['splinter_test_mode'] = 1
      else:
         raise Exception('Incorrect argument: ' + arg)

   args = ['modprobe', 'splinter'] + map(lambda x: x[0]+'='+str(x[1]), moduleOptions.items())
   exit(spawnvp(P_WAIT, 'modprobe', args))

def do_module_unload(args):
   """
   Unloads the kernel splinter module. All hooks are being unloaded too.
   It may happen that a hook is being in use, in such case, unload will fail.

   Examples:
      splinter module-unload
   """
   if not isModuleLoaded():
      print('\nSplinter not loaded...\n')
      exit(-1)
   exit(spawnvp(P_WAIT, 'rmmod', ['rmmod', 'splinter']))

def do_buffer_show(args):
   """
   Shows the content of a memory buffer. The buffer is a ring buffer, when
   overflown, dropped bytes counter is updated accordingly. Also by design,
   once read from buffer data is discarded (which imitates 'dmesg -c').

   Examples:
      splinter buffer-show
   """
   interface, dropped = getDefaultInterface(), 0
   while True:
      reply = interface.msg(netstringSet('SPLINTER_DUMP_REQ'))
      vals = netstringUnroll(reply)
      if (len(vals) != 3) or (vals[0] != 'SPLINTER_DUMP_ANS'):
         break
      dropped += int(vals[1]) # TODO what to do with this?
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

try:
   globals().get('do_' + call)(args)
except TypeError as e:
   do_help(args)

############################################################################
