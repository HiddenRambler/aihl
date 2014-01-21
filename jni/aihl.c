/*

Copyright (C) 2014 rambler@hiddenramblings.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
 
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <elf.h>
#include "aihl.h"

static t_logfunc *log = printf;

//------------
// Extracted from android linker
//------------
// Magic shared structures that GDB knows about.

typedef struct link_map_t {
  uintptr_t l_addr;
  char*  l_name;
  uintptr_t l_ld;
  struct link_map_t* l_next;
  struct link_map_t* l_prev;
} link_map_t;

typedef void (*linker_function_t)();

#define SOINFO_NAME_LEN 128
typedef struct soinfo {
    char name[SOINFO_NAME_LEN];
    const Elf_Phdr* phdr;
    size_t phnum;
    Elf_Addr entry;
    Elf_Addr base;
    unsigned size;

    uint32_t unused1;  // DO NOT USE, maintained for compatibility.

    Elf_Dyn* dynamic;

    uint32_t unused2; // DO NOT USE, maintained for compatibility
    uint32_t unused3; // DO NOT USE, maintained for compatibility

    struct soinfo* next;

    unsigned flags;

    const char* strtab;
    Elf_Sym* symtab;
    size_t nbucket;
    size_t nchain;
    unsigned* bucket;
    unsigned* chain;

	//------------------

  // This is only used by 32-bit MIPS, but needs to be here for
  // all 32-bit architectures to preserve binary compatibility.
  unsigned* plt_got;

  Elf_Rel* plt_rel;
  size_t plt_rel_count;

  Elf_Rel* rel;
  size_t rel_count;

  linker_function_t* preinit_array;
  size_t preinit_array_count;

  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;

  linker_function_t init_func;
  linker_function_t fini_func;

  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;

  size_t ref_count;
  link_map_t link_map;

  int constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  Elf_Addr load_bias;

} soinfo;

static Elf_Sym* lookup_symbol(soinfo *si, const char *symbolname) {
    Elf_Sym* symtab = si->symtab;
    const char *strtab = si->strtab;

    for(unsigned int i=1; i<si->nchain; i++) {
        Elf_Sym *s = symtab + i;
        const char *str = strtab + s->st_name;

        if (!strcmp(str, symbolname)) {
            log("Found symbol %s @ index %d with offset %x\n", str, i, s->st_value);
            return s;
        }
    }
    return NULL;
}


void *aihl_load_library(const char *libname) {
	void *handle = dlopen(libname, RTLD_GLOBAL);
	if (!handle) {
        log("Failed to load lib %s\n", libname);
	}
	
	return handle;
}

void *aihl_hook_symbol(void * libhandle, const char *symbolname, void *hookfunc) {
    soinfo *si = (soinfo *)libhandle;
    if (!si) {
        log("Invalid handle\n");
        return NULL;
    }

    Elf_Sym* symbol = lookup_symbol(si, symbolname);
    if (!symbol) {
        log("Failed to find symbol %s\n", symbolname);
        return NULL;
    }
    Elf32_Word originalfunc = si->load_bias + symbol->st_value;
    
    //todo we should keep a reference to original and return it
    if (originalfunc == (Elf32_Word)hookfunc) {
		log("Symbol %s already patched\n", symbolname);
		return NULL;
	}

    if (mprotect((void *)si->base, si->size, PROT_READ|PROT_WRITE|PROT_EXEC)) {
        log("Failed to make symbol table writable: %s\n", strerror(errno));
    }

    Elf32_Word hookoffset = (unsigned int)hookfunc - si->load_bias;
    symbol->st_value = hookoffset;

    //todo: we should reactivate the memory protections

    return (void *)originalfunc;
}

void aihl_set_log_func(t_logfunc *logger) {
	log = logger;
}
