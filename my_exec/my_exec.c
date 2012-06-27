/**
 * Coded by i4k
 * Rewrite of the algorithm used in linux kernel 3.4.4 (fs/binfmt_elf.c) to load
 * a ELF binary. I stripped the logic of prepare the stack and VM to execute the
 * ELF and I focused in the tests that the kernel make to ensure ELF consistency.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>

#define ASSERT(condition) do {                                          \
    if (!(condition)) {                                                 \
      fprintf(stderr, "[-] ASSERTION FAILED AT %s:%d\n", __FUNCTION__, __LINE__); \
      exit(1);                                                          \
    } } while(0)
                            
#define elf_check_arch(x)                       \
  (((x)->e_machine == EM_386))
	
#define PAGE_SIZE 4096
#define PAGE_OFFSET 0xc0000000
#define TASK_SIZE PAGE_OFFSET
#define ELF_EXEC_PAGESIZE 4096
#define ELF_ET_DYN_BASE (2 * TASK_SIZE / 3)

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS	0
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

                            
#define EXSTACK_DEFAULT 0 /* Whatever the arch defaults to */
#define EXSTACK_DISABLE_X 1 /* Disable executable stacks */
#define EXSTACK_ENABLE_X 2 /* Enable executable stacks */
                            
#define ENOMEM 2
#define ENOEXEC 3
#define EIO 4
#define ELIBBAD 5
#define EINVAL 6


typedef uint8_t _u8;

struct linux_binprm {
  _u8* mem;
  int file;
  int argc, envc;
  char filename[FILENAME_MAX];
  char interp[FILENAME_MAX];
  unsigned interp_flags;
  unsigned interp_data;
  struct stat st_info;
  unsigned long loader, exec;
};

#define SAY(fmt...) fprintf(stdout, fmt)
#define SAY_ERR(fmt...) fprintf(stderr, fmt)

void open_elf_binary(struct linux_binprm* elf) {
  elf->file = open(elf->filename, O_RDONLY);

  if (elf->file == -1) {
    SAY_ERR("[-] Erro ao abrir arquivo '%s'!\n", elf->filename);
    exit(1);
  }

  fstat(elf->file, &elf->st_info);

  elf->mem = mmap(0, elf->st_info.st_size, PROT_READ, MAP_SHARED, elf->file, 0);
	
  if (elf->mem == MAP_FAILED) {
    SAY_ERR("[-] mmap falhou!\n");
    exit(1);
  }
}

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)


int load_elf_binary(struct linux_binprm* bprm) {
  int retval = -1, i;
  int interp_fd;
  _u8* interp_buf = NULL;
  unsigned int size;
  unsigned long elf_bss, elf_brk;
  unsigned long load_bias = 0;
  char * elf_interpreter = NULL;
  ElfW(Phdr) *elf_phdata, *elf_ppnt;
  unsigned long start_code, end_code, start_data, end_data;
  int executable_stack = EXSTACK_DEFAULT;
  struct {
    ElfW(Ehdr) elf_ex;
    ElfW(Ehdr) interp_elf_ex;
  } *loc;
    
  loc = malloc(sizeof(*loc));
  if (!loc) {
    SAY_ERR("[-] error allocating memory\n");
    exit(1);
  }
    
  loc->elf_ex = *((ElfW(Ehdr) *) bprm->mem);
    
  /* Checagem básica para verificar se é ELF */
  if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
    SAY_ERR("[-] Not a ELF file...\n");
    goto out;
  }
    
  /* Verifica se é do tipo EXEC ou DYN */
  if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN) {
    goto out;
  }
    
  /* Agora lê todas as informações do header */
  if (loc->elf_ex.e_phentsize != sizeof(ElfW(Phdr)))
    goto out;
  if (loc->elf_ex.e_phnum < 1 ||
      loc->elf_ex.e_phnum > 65536U / sizeof(ElfW(Phdr)))
    goto out;
        
  size = loc->elf_ex.e_phnum * sizeof(ElfW(Phdr));
    
  retval = -ENOMEM;
  elf_phdata = malloc(size);
  if (!elf_phdata) {
    goto out;
  }
    
  elf_phdata = (ElfW(Phdr)*) (bprm->mem + loc->elf_ex.e_phoff);
  elf_ppnt = elf_phdata;
  elf_bss = 0;
  elf_brk = 0;
	
  start_code = ~0UL;
  end_code = 0;
  start_data = 0;
  end_data = 0;
	
  for (i = 0; i < loc->elf_ex.e_phnum; i++) {
    if (elf_ppnt->p_type == PT_INTERP) {
      retval = -ENOEXEC;
      if (elf_ppnt->p_filesz > FILENAME_MAX || 
          elf_ppnt->p_filesz < 2)
        goto out_free_ph;

      retval = -ENOMEM;
      elf_interpreter = malloc(elf_ppnt->p_filesz);
      if (!elf_interpreter)
        goto out_free_ph;

      bzero(elf_interpreter, elf_ppnt->p_filesz);
      /* Copy the name of interpreter */
      strncpy(elf_interpreter, (char*)(bprm->mem + elf_ppnt->p_offset), elf_ppnt->p_filesz);
      if (strlen(elf_interpreter) == 0) {
        retval = -EIO;
        goto out_free_interp;
      }
			
      /* make sure path is NULL terminated */
      retval = -ENOEXEC;
      if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0') {
        goto out_free_interp;
      }

      interp_fd = open(elf_interpreter, O_RDONLY);
      retval = -EIO;
      if (interp_fd == -1)
        goto out_free_interp;
		    
      struct stat interp_st;
      fstat(interp_fd, &interp_st);

      interp_buf = mmap(0, interp_st.st_size, PROT_READ, MAP_SHARED, interp_fd, 0);
			
      if (interp_buf == MAP_FAILED) {
        retval = -EIO;
        goto out_free_dentry;
      }

      /* Get the exec headers */
      loc->interp_elf_ex = *((ElfW(Ehdr) *)interp_buf);
      break;
    }
    elf_ppnt++;
  }
	
  elf_ppnt = elf_phdata;
  for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
    if (elf_ppnt->p_type == PT_GNU_STACK) {
      if (elf_ppnt->p_flags & PF_X)
        executable_stack = EXSTACK_ENABLE_X;
      else
        executable_stack = EXSTACK_DISABLE_X;
      break;
    }

  /* Some simple consistency checks for the interpreter */
  if (elf_interpreter) {
    retval = -ELIBBAD;
    /* Not an ELF interpreter */
    if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
      goto out_free_dentry;
    /* Verify the interpreter has a valid arch */
    if (!elf_check_arch(&loc->interp_elf_ex))
      goto out_free_dentry;
  }
	
  /* Now we do a little grungy work by mmapping the ELF image into
     the correct location in memory. */	
  for(i = 0, elf_ppnt = elf_phdata;
      i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
    int elf_prot = 0, elf_flags;
    unsigned long k, vaddr;

    if (elf_ppnt->p_type != PT_LOAD)
      continue;

    /* Segment is readable? */
    if (elf_ppnt->p_flags & PF_R)
      elf_prot |= PROT_READ;
    /* Segment is writable? */
    if (elf_ppnt->p_flags & PF_W)
      elf_prot |= PROT_WRITE;
    /* Segment is executable? */
    if (elf_ppnt->p_flags & PF_X)
      elf_prot |= PROT_EXEC;

    elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

    vaddr = elf_ppnt->p_vaddr;
    if (loc->elf_ex.e_type == ET_EXEC) {
      elf_flags |= MAP_FIXED;
    } else if (loc->elf_ex.e_type == ET_DYN) {
      /* Try and get dynamic programs out of the way of the
       * default mmap base, as well as whatever program they
       * might try to exec.  This is because the brk will
       * follow the loader, and is not movable.  */

      load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
    }

    k = elf_ppnt->p_vaddr;
    if (k < start_code)
      start_code = k;
    if (start_data < k)
      start_data = k;

    /*
     * Will check to see if section's size overflow the allowed task size
     */
    if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
        elf_ppnt->p_memsz > TASK_SIZE ||
        TASK_SIZE - elf_ppnt->p_memsz < k) {
      retval = -EINVAL;
      goto out_free_dentry;
    }

    k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

    if (k > elf_bss)
      elf_bss = k;
    if ((elf_ppnt->p_flags & PF_X) && end_code < k)
      end_code = k;
    if (end_data < k)
      end_data = k;
    k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
    if (k > elf_brk)
      elf_brk = k;
  }

  loc->elf_ex.e_entry += load_bias;
  elf_bss += load_bias;
  elf_brk += load_bias;
  start_code += load_bias;
  end_code += load_bias;
  start_data += load_bias;
  end_data += load_bias;

  SAY("loc->elf_ex.e_entry = 	0x%08x\n", loc->elf_ex.e_entry);
  SAY("elf_bss = 0x%08lx\n", elf_bss);
  SAY("elf_brk = 0x%08lx\n", elf_brk);    
  SAY("start_code = 0x%08lx\n", start_code);
  SAY("end_code = 0x%08lx\n", end_code);
  SAY("start_data = 0x%08lx\n", start_data);
  SAY("end_data = 0x%08lx\n", end_data);

  retval = 0;
  SAY("[+] successfull loaded!\n");
  goto out_ret;
	
 out:
  free(loc);
 out_ret:
  return retval;

  /* error cleanup */
 out_free_dentry:
  /*allow_write_access(interpreter);
    if (interpreter)
    fput(interpreter);*/
 out_free_interp:
  free(elf_interpreter);
 out_free_ph:
  free(elf_phdata);
  goto out;
  return retval;
}

int main(int argc, char** argv) {
  int retval = -1;
  struct linux_binprm *bprm = NULL;

  if (argc < 2) {
    SAY_ERR("usage:\n\t%s <elf-binary>\n", *argv);
    return 1;
  }
    
  printf("cloning linux kernel load executable code!\n\n");

  bprm = (struct linux_binprm*)malloc(sizeof(*bprm));
    
  if (!bprm) {
    fprintf(stderr, "[-] error allocating memory to binprm");
    return 1;
  }
    
  bzero(bprm->filename, FILENAME_MAX);
  bzero(bprm->interp, FILENAME_MAX);
    
  strncpy(bprm->filename, argv[1], FILENAME_MAX);
  strncpy(bprm->interp, argv[1], FILENAME_MAX);
  bprm->argc = 1;
  bprm->envc = 1;
    
  open_elf_binary(bprm);
   
  /* loading ELF */
  retval = load_elf_binary(bprm);
    
  switch(retval) {
  case 0:
    SAY("SUCCESS EXECUTION!\n");
    break;
  case -ENOMEM:
    SAY_ERR("[-] ENOMEM...\n");
    break;
  case -ENOEXEC:
    SAY_ERR("[-] ENOEXEC... \n");
    break;
  case -EIO:
    SAY_ERR("[-] ENOIO...\n");
    break;
  case -ELIBBAD:
    SAY_ERR("[-] ELIBBAD...\n");
    break;
  default:
    SAY("default ret = %d\n", retval);
    break;
  }

  ASSERT(bprm != NULL);    
  ASSERT(bprm->file != -1);
  ASSERT(bprm->mem != NULL && bprm->mem != MAP_FAILED);
    
  close(bprm->file);
  if (munmap(bprm->mem, bprm->st_info.st_size) != 0) {
    perror("munmap");
  }
  free(bprm);
    
  return 0;
}
