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
void ElfParse::write_json(char* tmp) {
    Json::Value root;
    Json::Value item;
    Json::Value arrayObject;
    //root["Info"] = Json::Value("magic");
    char elf_type[4] = {0x7f, 0x45, 0x4c, 0x46};


    if ((strncmp(elf_type, tmp, 4))==0)
    {
        for (int i = 0; i < 4; i++){
            item["key"]=elf_type[i];
            arrayObject.append(item);
           // printf("%0x ",elf_type[i]);
            //putchar('\n');
        }
    }
    root["Magic"]=arrayObject;


    Json::Value Info;
    Json::Value Diff;
    Json::Value temp;
    Json::Value temp1;
    for (int i = 4, j = 20; i < 7, j < 23; ++i, ++j) {
        switch (i) {
            case EI_CLASS:
                if (tmp[i] == ELFCLASSNONE)
                    Info["File Type"] = Json::Value("非法字符");
                //printf("%s\t", "非法字符");
                if (tmp[i] == ELFCLASS32)
                    Info["File Type"] = Json::Value("32位");
                //printf("%s\t", "32位");
                if (tmp[i] == ELFCLASS64)
                    Info["File Type"] = Json::Value("64位");
                //printf("%s\t", "64位");
                if (tmp[j] == ELFCLASSNONE)
                    Info["other File Type"] = Json::Value("非法字符");
                //printf("%s\t", "非法字符");
                if (tmp[j] == ELFCLASS32)
                    Info["other File Type"] = Json::Value("32位");
                //printf("%s\t", "32位");
                if (tmp[j] == ELFCLASS64)
                    Info["other File Type"] = Json::Value("64位");
                //printf("%s\t", "64位");
                if(tmp[i]!=tmp[j]) {
                    temp["File Type"]=tmp[i];
                    temp1["Other File Type"]=tmp[j];
                    Diff.append(temp);
                    Diff.append(temp1);
                }
                    break;
            case EI_DATA:
                if (tmp[i] == ELFDATA2LSB)
                    Info["Byte order"] = Json::Value("大端");
                //printf("%s\t", "大端");
                if (tmp[i] == ELFDATA2MSB)
                    Info["Byte order"] = Json::Value("小端");
                //printf("%s\t\t", "小端");
                if (tmp[j] == ELFDATA2LSB)
                    Info["Other Byte order"] = Json::Value("大端");
                //printf("%s\t", "大端");
                if (tmp[j] == ELFDATA2MSB)
                    Info["Other Byte order"] = Json::Value("小端");
                //printf("%s\t\t", "小端");
                if(tmp[i]!=tmp[j]) {
                    temp["Byte order"]=tmp[i];
                    temp1["Other Byte order"]=tmp[j];
                    Diff.append(temp);
                    Diff.append(temp1);
                }
                break;
            case EI_VERSION:
                Info["The Major Version"] = Json::Value("1");
                break;
            default:
                break;
        }
    }

    root["Info"] = Json::Value(Info);
    root["Diff"]=Json::Value(Diff);
    root["Name"] = Json::Value("ELF header");


    cout << "StyledWriter:" << endl;
    Json::StyledWriter bw;
    cout << bw.write(root) << endl << endl;

    //输出到文件
    ofstream os;
    os.open("demo.json", std::ios::out | std::ios::trunc);
    //if (!os.is_open())
    //  cout << "error：can not find or create the file which named \" demo.json\"." << endl;
    assert(os.is_open());
    os << bw.write(root);
    os.close();

    /*cout<<sw.write(root)<<endl<<endl;
    ofstream os;
    os.open("demo.json",ios::out | ios::app);
    if(!os.is_open())
        cout << "error：can not find or create the file which named \" demo.json\"." << endl;
    os<<bw.write(root);
    os.close();*/
}

void ElfParse::Start(ElfParse &elf, int argc, char **argv)
{
    //elf.fileheader(elf_header1,elf_header2,argc,argv);
    char* tmp=elf.fileheader(elf_header1,elf_header2,argc,argv);

    elf.write_json(tmp);
    /* for(int i = 0;i<EI_NIDENT*2;++i)
     {
         printf("%02X",tmp[i]);
         putchar(' ');
     }
     printf("\n");*/

    //cout<<tmp<<endl;
}