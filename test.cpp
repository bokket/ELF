//
// Created by bokket on 2020/12/8.
//

#include "ElfParse.cpp"
#include <iostream>
using namespace std;
int main(int argc,char* argv[])
{
    Elf64_Ehdr elf_header1;
    Elf64_Ehdr elf_header2;
    memset(&elf_header1,0,sizeof(elf_header1));
    memset(&elf_header2,0,sizeof(elf_header2));

    ElfParse elf(elf_header1,elf_header2);
    //elf.fileheader(elf_header1,elf_header2,argc,argv);
    char* tmp=elf.fileheader(elf_header1,elf_header2,argc,argv);
   /* for(int i = 0;i<EI_NIDENT*2;++i)
    {
        printf("%02X",tmp[i]);
        putchar(' ');
    }
    printf("\n");*/
    
    //cout<<tmp<<endl;
}