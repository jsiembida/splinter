

#include "splinter.h"


#define _U    15
#define _N     0
#define _E     1
#define _G     2
#define _V     3
#define _1     4
#define _2     5
#define _3     6
#define _4     7
#define _8     8

#define A(a, b)  (char)((0xff) & (((a)<<4) | (b)))

/*

#!/bin/bash

# A bash script to convert opcode file into C array entries.

i=0; for x in $(cat); do
  x1=${x:0:1}; x2=${x:1:1}
  echo -n " A(_${x1},_${x2}),"
  ((i=1+i))
  ((i%16)) || echo
done

*/

//
// This is a simplified one-byte opcode map, table A-2 as it is
// presented in Intel's Developers Manual, A-10 and A-11, Vol. 3B
//
static char __opcode_one_byte[] = {
 A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U), A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U),
 A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U), A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U),
 A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U), A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U),
 A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U), A(_E,_G), A(_E,_G), A(_G,_E), A(_G,_E), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U),
 A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N),
 A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_4,_N), A(_E,_4), A(_1,_N), A(_E,_1), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_E,_1), A(_E,_4), A(_E,_1), A(_E,_1), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_G), A(_E,_N), A(_E,_N), A(_N,_E), A(_E,_N),
 A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N),
 A(_N,_4), A(_N,_4), A(_4,_N), A(_4,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_1), A(_N,_4), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_1), A(_N,_4), A(_N,_4), A(_N,_4), A(_N,_4), A(_N,_4), A(_N,_4), A(_N,_4), A(_N,_4),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_E,_1), A(_E,_4), A(_3,_N), A(_N,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_1), A(_N,_1), A(_1,_N), A(_1,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_U,_U), A(_U,_U)
};

//
// This is a simplified two-bytes opcode map, table A-3 with no
// instruction prefixes, as it is presented in
// Intel's Developers Manual, A-10 and A-11, Vol. 3B
//
static char __opcode_two_bytes[] = {
 A(_U,_U), A(_U,_U), A(_G,_E), A(_G,_E), A(_U,_U), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_E,_N), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_E,_N),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_U,_U), A(_N,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N), A(_E,_N),
 A(_U,_U), A(_U,_U), A(_N,_N), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_N), A(_E,_G), A(_U,_U), A(_U,_U), A(_U,_U), A(_G,_E),
 A(_E,_G), A(_E,_G), A(_U,_U), A(_E,_G), A(_U,_U), A(_U,_U), A(_G,_E), A(_G,_E), A(_U,_U), A(_U,_U), A(_U,_U), A(_E,_G), A(_G,_E), A(_G,_E), A(_G,_E), A(_G,_E),
 A(_E,_G), A(_E,_G), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N), A(_N,_N),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U),
 A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U)
};

static char __opcode_group5_bytes[] = {
 A(_N,_E), A(_N,_E), A(_U,_U), A(_U,_U), A(_U,_U), A(_U,_U), A(_N,_E), A(_U,_U)
};

int splinter_code_disass(byte_p cur, disass_p dst)
{
  uint_t pre1, pre1_val;
  uint_t pre3, pre3_val;
  uint_t pre4, pre4_val;
  uint_t opcode, opcode_arg1, opcode_arg2;
  uint_t disp, disp_val;
  uint_t imm, imm_val;
  uint_t mod, mod_val, mod_rm, mod_reg;
  uint_t sib, sib_scale, sib_index, sib_base;
#ifdef __amd64__
  uint_t rex, rex_w, rex_r, rex_x, rex_b;
#endif
  byte_p tmp;
  char * opcodes_map = NULL;
  int32_t address;

  DEBUG();
  splinter_memory_dump("", cur);
  memset(dst, 0, disass_s);
  dst->code = cur;

  while(dst->parsed_len < 5)
  {
    tmp = cur;

    /*
    if (*cur == 0xe8 || *cur == 0xe9) {
      // jmp and call opcodes are handled separately
      dst->branch_opcode = *(cur++);
      address =*((int32_p)cur);
      dst->branch_offset = cur - dst->code;
      cur += int32_s;
      dst->branch_address = ((int_t)cur) + ((int_t)address);
      debug(DEBUG_ALL, "%p / %p relative branch %lx / %lx -> %lx",
        dst->code, tmp, (uint_t)dst->branch_opcode, (uint_t)address, (uint_t)dst->branch_address);
      memcpy(dst->parsed_buff + dst->parsed_len, tmp, 5);
      dst->parsed_len += 5;
      continue;
    }
    */

#ifdef __amd64__
    // ff 25 0e 01 00 00        jmpq   *0x10e(%rip)
    // ff 15 0e 01 00 00        callq  *0x10e(%rip)
    /*
    if (*cur == 0xff && (cur[1] == 0x15 || cur[1] == 0x25)) {
      dst->branch_opcode = cur[1];
      cur += 2;
      address =*((int32_p)cur);
      dst->branch_offset = cur - dst->code;
      cur += int32_s;
      dst->branch_address = ((int_t)cur) + ((int_t)address);
      debug(DEBUG_ALL, "%p relative (%%rip) branch %lx / %lx -> %lx",
        tmp, (uint_t)dst->branch_opcode, (uint_t)address, (uint_t)dst->branch_address);
      dst->parsed_len += 6;
      continue;
    }
    */
#else
    // ff 25 6c 96 04 08	jmp    *0x804966c
    // ff 15 6c 96 04 08	call   *0x804966c
    /*if (*cur == 0xff && (cur[1] == 0x15 || cur[1] == 0x25)) {
      cur += 6;
      memcpy(dst->parsed_buff + dst->parsed_len, tmp, cur - tmp);
      dst->parsed_len += 6;
      continue;
    }*/
#endif

    pre1 = pre3 = pre4 = opcode = mod = sib = disp = imm = 0;
#ifdef __amd64__
    rex = 0;
#endif

    // Prefixes supported only partially.
    for(; 1; cur++) {
      if(*cur == 0xf0 || *cur == 0xf2 || *cur == 0xf3) {
        if (pre1) return -1;
        pre1 = 1;
        pre1_val = *cur;
      } else if (*cur == 0x66) {
        if (pre3) return -1;
        pre3 = 1;
        pre3_val = *cur;
      } else if (*cur == 0x67) {
        if (pre4) return -1;
        pre4 = 1;
        pre4_val = *cur;
      } else {
        break;
      }
    }

#ifdef __amd64__
    rex = *cur;
    if(0x40 <= rex && rex <= 0x4f) {
      rex_w = (rex >> 3) & 1;
      rex_r = (rex >> 2) & 1;
      rex_x = (rex >> 1) & 1;
      rex_b = (rex >> 0) & 1;
      rex = 1;
      cur++;
    } else {
      rex = 0;
    }
#endif

    opcode = *cur++;
    opcodes_map = __opcode_one_byte;
    if(opcode == 0x0f) {
        // An escaped opcode, currently we only support
        // two-byte opcodes without extra prefixes.
        if (pre1 || pre3 || pre4)
            splinter_error_return(-1, "disassembly failed @ %p - prefixes unsupported in escaped opcodes", (cur - 1));
        opcodes_map = __opcode_two_bytes;
        opcode = *cur++;
    } else if (opcode == 0xff) {
        // Currently, only group 5 (seemingly in common use) supported
        opcodes_map = __opcode_group5_bytes;
        opcode = 7 & (*cur >> 3);
    }

    opcode_arg1 = (opcodes_map[opcode] >> 4) & 0x0f;
    opcode_arg2 = (opcodes_map[opcode] >> 0) & 0x0f;
    if(opcode_arg1 == _U || opcode_arg2 == _U)
        splinter_error_return(-1, "disassembly failed @ %p - unknown opcode 0x%02x", (cur - 1), opcode);
    if(opcode_arg1 == _E || opcode_arg2 == _E)
        mod = 1;
    if(opcode_arg1 == _1 || opcode_arg2 == _1)
        imm = 1;
    if(opcode_arg1 == _2 || opcode_arg2 == _2)
        imm = 2;
    if(opcode_arg1 == _3 || opcode_arg2 == _3)
        imm = 3;
    if(opcode_arg1 == _4 || opcode_arg2 == _4)
        imm = 4;

    if(mod) {
        mod = *cur++;
        mod_rm = mod & 7;
        mod_reg = (mod >> 3) & 7;
        mod_val = (mod >> 6) & 3;
        mod = 1;
        switch (mod_val)
        {
        case 0:
            if(mod_rm == 4)
                sib = 1;
            if(mod_rm == 5)
                disp = 4;
            break;
        case 1:
            if(mod_rm == 4)
                sib = 1;
            disp = 1;
            break;
        case 2:
            if(mod_rm == 4)
                sib = 1;
            disp = 4;
            break;
        }
    } else {
        mod = 0;
    }

    if(sib) {
        sib = *cur++;
        sib_scale = (sib >> 6) & 3;
        sib_index = (sib >> 3) & 7;
        sib_base = sib & 7;
        sib = 1;
        if(sib_base == 5) {
            if(mod_val == 0 || mod_val == 2)
                disp = 4;
            else if(mod_val == 1)
                disp = 1;
        }
    } else {
        sib = 0;
    }

    if(disp == 1) {
        disp_val = *cur++;
    } else if(disp == 4) {
        disp_val = *cur++;
        disp_val = (disp_val << 8) | *cur++;
        disp_val = (disp_val << 16) | *cur++;
        disp_val = (disp_val << 24) | *cur++;
        disp = 1;
    } else {
        disp = 0;
    }

    if(0 < imm && imm <= 4) {
        for(imm_val = *cur++; imm > 1; imm--)
            imm_val = (imm_val << 8) | *cur++;
        imm = 1;
    } else {
        imm = 0;
    }
    memcpy(dst->parsed_buff + dst->parsed_len, tmp, cur - tmp);
    dst->parsed_len += cur - tmp;
  }

  DEBUG("analyzed %d bytes", dst->parsed_len);
  return dst->parsed_len;
}

int splinter_code_copy(byte_p dst, disass_p src) {
    memcpy(dst, src->parsed_buff, src->parsed_len);
    return src->parsed_len;
}

int splinter_code_patch(byte_p dst, disass_p src) {
    byte_p tmp = dst;
    DEBUG();
    splinter_memory_dump("before patching", tmp);
    splinter_code_copy(dst, src);
    if (src->branch_opcode == 0xe8
        || src->branch_opcode == 0xe9
#ifdef __amd64__
        || src->branch_opcode == 0x15
        || src->branch_opcode == 0x25
#endif
       ) {
      dst += src->branch_offset;
      *((int32_p)dst) = (int32_t)(src->branch_address - ((int_t)(dst + int32_s)));
    }
    splinter_memory_dump("after patching", tmp);
    return src->parsed_len;
}

