//
// Created by bokket on 2020/12/9.
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
    elf.Start(elf,argc,argv);
}