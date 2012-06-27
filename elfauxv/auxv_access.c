#include <stdio.h>
#include <elf.h>

main(int argc, char* argv[], char* envp[])
{
        int a;
        Elf32_auxv_t *auxv;
        while(*envp++ != NULL);

        for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
        {
                if( auxv->a_type == AT_RANDOM)
                        printf("AT_RANDOM is: 0x%x\n", auxv->a_un.a_val);
        }
        
        printf("variable a at address %p\n", &a);
}


