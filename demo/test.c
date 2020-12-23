#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

int main(int argc,char* argv[])
{
        if(argc < 2){ exit(0); }
        FILE *fp;
        Elf64_Ehdr elf_header;

        fp = fopen(argv[1],"r");
        if(fp == NULL) { exit(0); }

        int readfile;
        readfile = fread(&elf_header,sizeof(Elf64_Ehdr),1,fp);
        if(readfile == 0){ exit(0); }

        if(elf_header.e_ident[0] == 0x7F || elf_header.e_ident[1] == 'E')
        {
                printf("头标志: ");
                for(int x =0;x<16;x++)
                {
                        printf("%x ",elf_header.e_ident[x]);
                }
                printf("\n");
        }
        return 0;
}