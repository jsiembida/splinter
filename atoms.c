

/******************************************/

#include "splinter.h"

/******************************************/


static atom_p __atoms_chain = NULL;
static atom_p __atoms_buffer = NULL;
uint_t stats_atoms_total = 0;
uint_t stats_atoms_total_bytes = 0;
uint_t stats_atoms_free = 0;
uint_t stats_atoms_free_bytes = 0;
uint_t stats_atoms_used = 0;
uint_t stats_atoms_used_bytes = 0;


static void __atom_free_plain(atom_p a) {
  // DEBUG("atom = %p", a);
  if (!a->free) return;
  a->free = NULL;
  a->call = operator_null;
  a->data = 0;
  a->next = __atoms_chain;
  __atoms_chain = a;
  stats_atoms_used -= 1;
  stats_atoms_used_bytes -= atom_s;
  stats_atoms_free += 1;
  stats_atoms_free_bytes += atom_s;
}


static void __atom_free_string(atom_p a) {
  // DEBUG();
  string_free((byte_p *)(&(a->data)));
  __atom_free_plain(a);
}


static void __atom_free_list(atom_p a) {
  // DEBUG();
  atom_free((atom_p)(a->data));
  __atom_free_plain(a);
}


atom_p atom_free(atom_p a) {
  atom_p b = NULL;
  // DEBUG();
  for(; a != NULL; a = b) {
    b = a->next;
    if (a->free) a->free(a);
    else __atom_free_plain(a);
  }
  return NULL;
}


atom_p atom_alloc_plain(atom_data_callback_t h, uint_t val)
{
  atom_p curr_atom = NULL;
  DEBUG();

  if(__atoms_chain)
  {
    curr_atom = __atoms_chain;
    __atoms_chain = curr_atom->next;
    curr_atom->next = NULL;
    curr_atom->call = h;
    curr_atom->data = val;
    curr_atom->free = __atom_free_plain;

    stats_atoms_used += 1;
    stats_atoms_used_bytes += atom_s;
    stats_atoms_free -= 1;
    stats_atoms_free_bytes -= atom_s;
  }

  return curr_atom;
}


atom_p atom_alloc_string(atom_data_callback_t h, char * start, char * stop) {
  atom_p a = atom_alloc_plain(h, 0);
  DEBUG();

  if (a) {
    a->free = __atom_free_string;
    if (string_alloc((byte_p *)(&(a->data)))) {
      return atom_free(a);
    }
    for(; start < stop; start++) {
      if (string_append((byte_p *)(&atom_data(a)), *start)) {
        return atom_free(a);
      }
    }
  }
  return a;
}


atom_p atom_alloc_list(atom_data_callback_t h, atom_p list) {
  atom_p a = atom_alloc_plain(h, (uint_t)list);
  DEBUG();

  if (a) {
    a->free = __atom_free_list;
  }
  return a;
}


int atoms_init(uint_t size) {
  uint_t i;
  atom_p curr_atom = NULL, prev_atom = NULL;
  debug(DEBUG_INF, "size = %lu", size);

  if (!size) return atoms_cleanup();
  if (__atoms_buffer) return -1;
  if ((__atoms_buffer = splinter_memory_alloc(size * atom_s)) == NULL) {
    debug(DEBUG_ERR, "could not alloc atoms buffer");
    return -1;
  }
  memset(__atoms_buffer, 0, size * atom_s);
  curr_atom = __atoms_chain = __atoms_buffer;
  for(i = 0; i < size; i++, prev_atom = curr_atom++) {
    curr_atom->call = operator_null;
    if (prev_atom) {
      prev_atom->next = curr_atom;
    }
  }
  stats_atoms_total = stats_atoms_free = size;
  stats_atoms_total_bytes = stats_atoms_free_bytes = size * atom_s;
  stats_atoms_used = stats_atoms_used_bytes = 0;
  debug(DEBUG_DBG, "atoms buffer = %p - %p", __atoms_buffer, ((byte_p)__atoms_buffer) + size * atom_s);
  return 0;
}


int atoms_cleanup(void) {
  uint_t i;
  atom_p curr_atom = NULL;

  if (!__atoms_buffer) return -1;
  DEBUG();
  for(i = 0, curr_atom = __atoms_buffer; i < stats_atoms_total; i++) {
    atom_free(curr_atom);
  }
  __atoms_buffer = splinter_memory_free(__atoms_buffer);
  __atoms_chain = NULL;
  stats_atoms_total = stats_atoms_free = stats_atoms_used = 0;
  stats_atoms_total_bytes = stats_atoms_free_bytes = stats_atoms_used_bytes = 0;
  return 0;
}
