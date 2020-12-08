//
// Created by bokket on 2020/12/8.
//

#include "ElfParse.h"
char* ElfParse::fileheader(Elf64_Ehdr elf_header1, Elf64_Ehdr elf_header2, int argc, char **argv)
{
    if(argc<3)
    {
        error("option error",__LINE__);
        exit(1);
    }
    int fd;
    int fd1;
    fd=open(argv[1],O_RDONLY);
    fd1=open(argv[2],O_RDONLY);

    if(fd<0 || fd1<0)
    {
        error("open error\n",__LINE__);
        exit(1);
    }

    int rfd;
    int rfd1;
    rfd=read(fd,&elf_header1,16);
    rfd1=read(fd1,&elf_header2,16);
    if(rfd<0 || rfd1<0)
    {
        error("read error\n",__LINE__);
        close(fd);
        close(fd1);
        exit(1);
    }

    char elf_type[4] = {0x7f, 0x45, 0x4c, 0x46};

    char s1[EI_NIDENT];
    char s2[EI_NIDENT];
    //char s3[EI_NIDENT*2];
   // const char* s1;
   // const char* s2;


    if(elf_header1.e_ident[0]==0x7f && elf_header1.e_ident[1]==0x45 && elf_header1.e_ident[2]==0x4c && elf_header1.e_ident[3]==0x46
    && elf_header2.e_ident[0]==0x7f && elf_header2.e_ident[1]==0x45 && elf_header2.e_ident[2]==0x4c && elf_header2.e_ident[3]==0x46)
    {
    /*if(elf_header1.e_ident[0] == 0x7F || elf_header1.e_ident[1] == 'E'
    && elf_header2.e_ident[0] == 0x7F || elf_header2.e_ident[1] == 'E')
    {*/
        printf("ELF Header:\r\n");
        //Magic
        printf("  Magic:   ");
        for(int i = 0;i<EI_NIDENT;++i)   //e_ident[EI_NIDENT]
        {
            printf("%02X", elf_header1.e_ident[i]);
            putchar(' ');
            s1[i]=elf_header1.e_ident[i];
            //printf("%x \n",s1[i]);
        }
        putchar('\n');
        printf("  Magic:   ");
        for(int i = 0;i<EI_NIDENT;++i)   //e_ident[EI_NIDENT]
        {
            printf("%02X", elf_header2.e_ident[i]);
            putchar(' ');
            s2[i]=elf_header2.e_ident[i];

            //printf("%x \n",s2[i]);
        }
        //if(s1.compare(s2)==0)
        if(strcmp(s1,s2)==0)
        {
            //printf("1");
            printf("\n\n\n\n");
            printf("Magic same:   ");
            putchar('\n');
            for(int i = 0;i<EI_NIDENT;++i)
            {
                printf("%02X\t%02X",elf_header1.e_ident[i],elf_header2.e_ident[i]);
                putchar('\n');
            }

            for(int i = 0;i<EI_NIDENT;++i)
            {
                s3[i]=s1[i];
                printf("%02x",s3[i]);
                putchar(' ');
            }
            printf("\n");
            int j=0;
            for(int i = EI_NIDENT;i<EI_NIDENT*2;++i)
            {
                s3[i]=s2[j];
                j++;
                printf("%02x",s3[i]);
                putchar(' ');
            }
            printf("\n");
            return s3;
        }
        else
        {
            printf("\n\n\n\n");
            printf("Magic diff:   ");
            putchar('\n');
            for(int i = 0;i<EI_NIDENT;++i)
            {
                s3[i]=s1[i];
                printf("%02X",s3[i]);
                putchar(' ');
            }
            printf("\n");
            int j=0;
            for(int i = EI_NIDENT;i<EI_NIDENT*2;++i)
            {
                s3[i]=s2[j];
                j++;
                printf("%02X",s3[i]);
                putchar(' ');
            }
            printf("\n");

            for(int i = 4;i<7;++i)
            {
                switch (i)
                {
                    case EI_CLASS:
                        if(s1[i]!=s2[i]) {
                            printf("%02X\t%02X\t\t\033[41;33m %s \033[0m\n", elf_header1.e_ident[i],
                                   elf_header2.e_ident[i], "EI_CLASS");
                            if (s1[i] == ELFCLASSNONE)
                                printf("%s\t", "非法字符");
                            if (s1[i] == ELFCLASS32)
                                printf("%s\t", "32位");
                            if (s1[i] == ELFCLASS64)
                                printf("%s\t", "64位");
                            if (s2[i] == ELFCLASSNONE)
                                printf("%s\t", "非法字符");
                            if (s2[i] == ELFCLASS32)
                                printf("%s\t", "32位");
                            if (s2[i] == ELFCLASS64)
                                printf("%s\t", "64位");
                        }
                        //strcat(tmp,s1[i]);
                        //strcat(tmp,s2[i]);
                        /*tmp.push_back(s1[i]);
                        tmp.push_back(s2[i]);
                        printf("\n");*/
                        break;
                    case EI_DATA:
                        if(s1[i]!=s2[i]) {
                            printf("%02X\t%02X\t\t\033[41;33m %s \033[0m\n", elf_header1.e_ident[i],
                                   elf_header2.e_ident[i], "EI_DATA");
                            if (s1[i] == ELFDATA2LSB)
                                printf("%s\t", "大端");
                            if (s1[i] == ELFDATA2MSB)
                                printf("%s\t\t", "小端");
                            if (s2[i] == ELFDATA2LSB)
                                printf("%s\t", "大端");
                            if (s2[i] == ELFDATA2MSB)
                                printf("%s\t\t", "小端");
                        }
                        printf("\n");
                        break;
                    case EI_VERSION:
                        if(s1[i]!=s2[i])
                            printf("%02X\t%02X\t\t\033[41;33m %s \033[0m",elf_header1.e_ident[i],elf_header2.e_ident[i],"EI_VERSION");
                        printf("\n");
                        break;
                    default:
                        break;
                }
                /*if(elf_header1.e_ident[i]!=elf_header2.e_ident[i])
                    printf("%02X\t%02X",elf_header1.e_ident[i],elf_header2.e_ident[i]);*/
               // printf("\n");
            }
            return s3;
        }
    }
    else
    {
        error("this is not ELF\n",__LINE__);
        close(fd);
        close(fd1);
        exit(1);
    }
}
void ElfParse::error(const char *str, const int line)
{
    perror(str);
    printf("line:%d", line);
}
int my_strcmp (char * str1,char * str2 )
{
    while (*str1==*str2 && *str1!='\0')
        ++str1, ++str2;

    return *str1-*str2;
}
