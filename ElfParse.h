//
// Created by bokket on 2020/12/8.
//

#ifndef ELF_ELFPARSE_H
#define ELF_ELFPARSE_H
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
using namespace std;


typedef uint16_t Elf64_Half; //16
typedef uint32_t Elf64_Word; //32
typedef uint64_t Elf64_Addr; //64
typedef uint64_t Elf64_Off;  //64
#define EI_NIDENT (16)

#define EI_CLASS	4		/* File class byte index */
#define ELFCLASSNONE	00		/* Invalid class */
#define ELFCLASS32	01		/* 32-bit objects */
#define ELFCLASS64	02		/* 64-bit objects */


#define EI_DATA		5		/* Data encoding byte index */
#define ELFDATANONE	00		/* Invalid data encoding */
#define ELFDATA2LSB	01		/* 2's complement, little endian */
#define ELFDATA2MSB	02		/* 2's complement, big endian */


#define EI_VERSION  6
#define EV_NONE		00		/* Invalid ELF version */
#define EV_CURRENT	01		/* Current version */

typedef struct
{
    unsigned char e_ident[EI_NIDENT];     /* 一个字节数组用来确认文件是否是一个ELF文件 */
    Elf64_Half    e_type;                 /* 描述文件是,可执行文件elf=2,重定位so=3 */
    Elf64_Half    e_machine;              /* 目标主机架构 */
    Elf64_Word    e_version;              /* ELF文件格式的版本 */
    Elf64_Addr    e_entry;                /* 入口点虚拟地址 */
    Elf64_Off     e_phoff;                /* 程序头文件偏移 */
    Elf64_Off     e_shoff;                /* 节头表文件偏移 */
    Elf64_Word    e_flags;                /* ELF文件标志 */
    Elf64_Half    e_ehsize;               /* ELF头大小 */
    Elf64_Half    e_phentsize;            /* 程序头大小 */
    Elf64_Half    e_phnum;                /* 程序头表计数 */
    Elf64_Half    e_shentsize;            /* 节头表大小 */
    Elf64_Half    e_shnum;                /* 节头表计数 */
    Elf64_Half    e_shstrndx;             /* 字符串表索引节头 */
} Elf64_Ehdr;

class ElfParse
{
public:
    ElfParse( Elf64_Ehdr elf_header1_,Elf64_Ehdr elf_header2_)
            :elf_header1(elf_header1_)
            ,elf_header2(elf_header2_)
    {}
    ~ElfParse(){}
//读取文件头函数
    void fileheader(Elf64_Ehdr elf_header1,Elf64_Ehdr elf_header2,int argc,char** argv);
    void start();
    void error(const char* str, const int line);

private:
    Elf64_Ehdr elf_header1;
    Elf64_Ehdr elf_header2;
};

int my_strcmp (char * str1,char * str2 );
#endif //ELF_ELFPARSE_H
