#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#define __USE_GNU
#include <sys/mman.h>
#include <link.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include <math.h>

#include "reload/plthook.h"

void test();

/*void *elf_hook(char const *module_filename,
               void const *module_address, char const *name, void const *substitution)
{
    static size_t pagesize;

    int descriptor;  //file descriptor of shared module

    Elf64_Shdr
            *dynsym = NULL,  // ".dynsym" section header
            *rel_plt = NULL,  // ".rel.plt" section header
            *rel_dyn = NULL;  // ".rel.dyn" section header

    Elf64_Sym
            *symbol = NULL;  //symbol table entry for symbol named "name"

    Elf64_Rel
            *rel_plt_table = NULL,  //array with ".rel.plt" entries
            *rel_dyn_table = NULL;  //array with ".rel.dyn" entries

    size_t
            i,
            name_index = 0,  //index of symbol named "name" in ".dyn.sym"
            rel_plt_amount = 0,  // amount of ".rel.plt" entries
            rel_dyn_amount = 0,  // amount of ".rel.dyn" entries
            *name_address = NULL;  //address of relocation for symbol named "name"

    void *original = NULL;  //address of the symbol being substituted

    if (NULL == module_address || NULL == name || NULL == substitution)
        return original;

    if (!pagesize)
        pagesize = sysconf(_SC_PAGESIZE);

    descriptor = open(module_filename, O_RDONLY);

    if (descriptor < 0)
        return original;

    if (
            section_by_type(descriptor, SHT_DYNSYM, &dynsym) ||  //get ".dynsym" section
            //actually, we need only the index of symbol named "name" in the ".dynsym" table
            symbol_by_name(descriptor, dynsym, name, &symbol, &name_index) ||
            //get ".rel.plt" (for 32-bit) or ".rela.plt" (for 64-bit) section
            section_by_name(descriptor, REL_PLT, &rel_plt) ||
            section_by_name(descriptor, REL_DYN, &rel_dyn)
        //get ".rel.dyn" (for 32-bit) or ".rela.dyn" (for 64-bit) section
            )
    {  //if something went wrong
        free(dynsym);
        free(rel_plt);
        free(rel_dyn);
        free(symbol);
        close(descriptor);

        return original;
    }
//release the data used
    free(dynsym);
    free(symbol);

    rel_plt_table = (Elf64_Rel *)(((size_t)module_address) + rel_plt->sh_addr);  //init the ".rel.plt" array
    rel_plt_amount = rel_plt->sh_size / sizeof(Elf64_Rel);  //and get its size

    rel_dyn_table = (Elf64_Rel *)(((size_t)module_address) + rel_dyn->sh_addr);  //init the ".rel.dyn" array
    rel_dyn_amount = rel_dyn->sh_size / sizeof(Elf64_Rel);  //and get its size
//release the data used
    free(rel_plt);
    free(rel_dyn);
//and descriptor
    close(descriptor);
//now we've got ".rel.plt" (needed for PIC) table
//and ".rel.dyn" (for non-PIC) table and the symbol's index
    for (i = 0; i < rel_plt_amount; ++i)  //lookup the ".rel.plt" table
        if (ELF64_R_SYM(rel_plt_table[i].r_info) == name_index)
            //if we found the symbol to substitute in ".rel.plt"
        {
            original = (void *)*(size_t *)(((size_t)module_address) +
                                           rel_plt_table[i].r_offset);  //save the original function address
            *(size_t *)(((size_t)module_address) +
                        rel_plt_table[i].r_offset) = (size_t)substitution;
            //and replace it with the substitutional

            break;  //the target symbol appears in ".rel.plt" only once
        }

    if (original)
        return original;
//we will get here only with 32-bit non-PIC module
    for (i = 0; i < rel_dyn_amount; ++i)  //lookup the ".rel.dyn" table
        if (ELF64_R_SYM(rel_dyn_table[i].r_info) == name_index)
            //if we found the symbol to substitute in ".rel.dyn"
        {
            name_address = (size_t *)(((size_t)module_address) + rel_dyn_table[i].r_offset);
            //get the relocation address (address of a relative CALL (0xE8) instruction's argument)

            if (!original)
                original = (void *)(*name_address + (size_t)name_address + sizeof(size_t));
            //calculate an address of the original function by a relative CALL (0xE8) instruction's argument

            mprotect((void *)(((size_t)name_address) & (((size_t)-1) ^ (pagesize - 1))),
                     pagesize, PROT_READ | PROT_WRITE);  //mark a memory page that contains the relocation as writable

            if (errno)
                return NULL;

            *name_address = (size_t)substitution - (size_t)name_address - sizeof(size_t);
            //calculate a new relative CALL (0xE8) instruction's argument for the substitutional function and write it down

            mprotect((void *)(((size_t)name_address) & (((size_t)-1) ^ (pagesize - 1))),
                     pagesize, PROT_READ | PROT_EXEC);  //mark a memory page that contains the relocation back as executable

            if (errno)  //if something went wrong
            {
                *name_address = (size_t)original -
                                (size_t)name_address - sizeof(size_t);  //then restore the original function address

                return NULL;
            }
        }

    return original;
}*/

void reload()
{
    /*void* handle = dlopen ("libreloader.so", RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND);
    if (!handle)
    {
        fprintf (stderr, "%s\n", dlerror());
        exit(1);
    }
    dlerror();

    struct link_map* lmap = NULL;
    assert(!dlinfo(handle, RTLD_DI_LINKMAP, &lmap));
    Elf64_Addr addr = lmap->l_addr;
    const Elf64_Ehdr* elfHeader = (Elf64_Ehdr*) addr;
    size_t sectionHeaderSize = elfHeader->e_shnum * elfHeader->e_shentsize;
    Elf64_Shdr* sectionHeader = (Elf64_Shdr*) calloc(1, sectionHeaderSize);

    int fd = open("libreloader.so", O_RDONLY, 0);
    size_t offset = elfHeader->e_shoff;
    assert(lseek(fd, offset, SEEK_SET) == offset);
    assert(read(fd, sectionHeader, sectionHeaderSize) == sectionHeaderSize);

    Elf64_Rela* plt = (Elf64_Rela*) (elfHeader + sectionHeader->sh_addr);
    size_t plt_cnt = sectionHeader->sh_size / sizeof(Elf64_Rela);

    for (int i = 0; i < plt_cnt; i++)
    {
        const Elf64_Rela* pltEntry = plt + i;
        if (ELF64_R_TYPE(plt->r_info) == R_X86_64_JUMP_SLOT)
        {
            void** addr_out = (void**) (elfHeader + pltEntry->r_offset);
            *addr_out = (void*) my_test;
            break;
        }
    }

    dlclose(handle);*/
}

static Elf64_Phdr programHeaders[32];
static struct dl_phdr_info libraryInfo;

static int header_list(struct dl_phdr_info* info, size_t size, void* data)
{
    printf("name=%s (%d segments) address=%p\n",
           info->dlpi_name, info->dlpi_phnum, (void*)info->dlpi_addr);
    for (int j = 0; j < info->dlpi_phnum; j++) {
        printf("\t\t header %2d: address=%10p\n", j,
               (void*) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
        printf("\t\t\t type=%u, flags=0x%X\n",
               info->dlpi_phdr[j].p_type, info->dlpi_phdr[j].p_flags);
    }
    printf("\n");
    return 0;
}
static int header_handler(struct dl_phdr_info* info, size_t size, void* data)
{
    if (!strcmp(info->dlpi_name, "/home/kobzol/Desktop/test/bin/libreloader.so"))
    {
        libraryInfo = *info;
        for (int j = 0; j < info->dlpi_phnum; j++)
        {
            programHeaders[j] = info->dlpi_phdr[j];
        }
    }

    return 0;
}

void load_file(const char* path, char* buffer)
{
    FILE* f = fopen(path, "r");
    fseek(f, 0L, SEEK_END);
    ssize_t size = ftell(f);
    rewind(f);
    fread(buffer, 1, (size_t) size, f);
    fclose(f);
}
void replace_program_header(void* baseAddress, Elf64_Phdr* header, char* library)
{
    if (!(header->p_flags & PF_X) && header->p_type == 1)
    {
        return;
    }

    int flags = 0;
    if (header->p_flags & PF_X)
    {
        flags |= PROT_EXEC;
    }
    if (header->p_flags & PF_R)
    {
        flags |= PROT_READ;
    }

    void* textMemoryAddress = baseAddress + header->p_vaddr;
    void* pageAddress = (void*)((long)(baseAddress + header->p_vaddr) & ~(4096UL));
    size_t pageSize = ((size_t) ceil(header->p_memsz / 4096.0)) * 4096;
    printf("Replacing segment (type %d) at %p with size %lu (page %p, %lu bytes)\n", header->p_type, textMemoryAddress, header->p_memsz, pageAddress, pageSize);

    //if (!(header->p_flags & PF_W))
    {
        int error = mprotect(pageAddress, pageSize, flags | PROT_WRITE);
        if (error)
        {
            printf("errno: %d\n", errno);
            perror("error");
        }
    }

    memcpy(textMemoryAddress, library + header->p_offset, header->p_filesz);
    if (header->p_memsz > header->p_filesz)
    {
        //memset(textMemoryAddress + header->p_filesz, 0, header->p_memsz - header->p_filesz);
    }
    //if (!(header->p_flags & PF_W))
    {
        int error = mprotect(pageAddress, pageSize, flags);
        if (error)
        {
            printf("revert errno: %d\n", errno);
            perror("revert");
        }
    }
}

int main()
{  
    printf("%d\n", getpid());

    //dl_iterate_phdr(header_list, NULL);
    dl_iterate_phdr(header_handler, NULL);

    char* buffer = malloc(1024 * 1024 * 5);

    while (1)
    {
        int x;
        scanf("%d", &x);

        void* handle = dlopen ("libreloader.so", RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND);
        struct link_map* lmap = NULL;
        assert(!dlinfo(handle, RTLD_DI_LINKMAP, &lmap));

        printf("handle %p\n", handle);
        printf("addr %p %p\n", (void*) lmap->l_addr, lmap->l_ld);
        dlclose(handle);

        load_file("libreloader.so", buffer);
        void* baseAddr = (void*) libraryInfo.dlpi_addr;

        for (int j = 0; j < libraryInfo.dlpi_phnum; j++)
        {
            replace_program_header(baseAddr, programHeaders + j, buffer);
        }

        test();
    }

    free(buffer);

    return 0;
}
