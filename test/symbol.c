#include <stdio.h>
#include <linux/elf.h>
#include <bfd.h>
#include <getopt.h>

//获取数组长度
#define NUM_ELEM(array) 	(sizeof (array) / sizeof ((array)[0]))


Elf_Internal_Shdr *     section_headers;
Elf_Internal_Sym *	dynamic_symbols;
Elf_Internal_Syminfo *	dynamic_syminfo;
//展示名？
int			show_name;
//字符表
char *			string_table;
unsigned long		string_table_length;
//动态字符数组
char *			dynamic_strings;
unsigned long           num_dynamic_syms;


//版本信息?
int			version_info[16];
//动态信息
int			dynamic_info[DT_JMPREL + 1];

static bfd_boolean get_file_header (Filedata * filedata)
{
  /* Read in the identity array.  */
  if (fread (filedata->file_header.e_ident, EI_NIDENT, 1, filedata->handle) != 1)
    return FALSE;

  /* Determine how to read the rest of the header.  */
  switch (filedata->file_header.e_ident[EI_DATA])
    {
    default:
    case ELFDATANONE:
    case ELFDATA2LSB:
      byte_get = byte_get_little_endian;
      byte_put = byte_put_little_endian;
      break;
    case ELFDATA2MSB:
      byte_get = byte_get_big_endian;
      byte_put = byte_put_big_endian;
      break;
    }

  /* For now we only support 32 bit and 64 bit ELF files.  */
  is_32bit_elf = (filedata->file_header.e_ident[EI_CLASS] != ELFCLASS64);

  /* Read in the rest of the header.  */
  if (is_32bit_elf)
    {
      Elf32_External_Ehdr ehdr32;

      if (fread (ehdr32.e_type, sizeof (ehdr32) - EI_NIDENT, 1, filedata->handle) != 1)
	return FALSE;

      filedata->file_header.e_type      = BYTE_GET (ehdr32.e_type);
      filedata->file_header.e_machine   = BYTE_GET (ehdr32.e_machine);
      filedata->file_header.e_version   = BYTE_GET (ehdr32.e_version);
      filedata->file_header.e_entry     = BYTE_GET (ehdr32.e_entry);
      filedata->file_header.e_phoff     = BYTE_GET (ehdr32.e_phoff);
      filedata->file_header.e_shoff     = BYTE_GET (ehdr32.e_shoff);
      filedata->file_header.e_flags     = BYTE_GET (ehdr32.e_flags);
      filedata->file_header.e_ehsize    = BYTE_GET (ehdr32.e_ehsize);
      filedata->file_header.e_phentsize = BYTE_GET (ehdr32.e_phentsize);
      filedata->file_header.e_phnum     = BYTE_GET (ehdr32.e_phnum);
      filedata->file_header.e_shentsize = BYTE_GET (ehdr32.e_shentsize);
      filedata->file_header.e_shnum     = BYTE_GET (ehdr32.e_shnum);
      filedata->file_header.e_shstrndx  = BYTE_GET (ehdr32.e_shstrndx);
    }
  else
    {
      Elf64_External_Ehdr ehdr64;

      /* If we have been compiled with sizeof (bfd_vma) == 4, then
	 we will not be able to cope with the 64bit data found in
	 64 ELF files.  Detect this now and abort before we start
	 overwriting things.  */
      if (sizeof (bfd_vma) < 8)
	{
	  error (_("This instance of readelf has been built without support for a\n\
64 bit data type and so it cannot read 64 bit ELF files.\n"));
	  return FALSE;
	}

      if (fread (ehdr64.e_type, sizeof (ehdr64) - EI_NIDENT, 1, filedata->handle) != 1)
	return FALSE;

      filedata->file_header.e_type      = BYTE_GET (ehdr64.e_type);
      filedata->file_header.e_machine   = BYTE_GET (ehdr64.e_machine);
      filedata->file_header.e_version   = BYTE_GET (ehdr64.e_version);
      filedata->file_header.e_entry     = BYTE_GET (ehdr64.e_entry);
      filedata->file_header.e_phoff     = BYTE_GET (ehdr64.e_phoff);
      filedata->file_header.e_shoff     = BYTE_GET (ehdr64.e_shoff);
      filedata->file_header.e_flags     = BYTE_GET (ehdr64.e_flags);
      filedata->file_header.e_ehsize    = BYTE_GET (ehdr64.e_ehsize);
      filedata->file_header.e_phentsize = BYTE_GET (ehdr64.e_phentsize);
      filedata->file_header.e_phnum     = BYTE_GET (ehdr64.e_phnum);
      filedata->file_header.e_shentsize = BYTE_GET (ehdr64.e_shentsize);
      filedata->file_header.e_shnum     = BYTE_GET (ehdr64.e_shnum);
      filedata->file_header.e_shstrndx  = BYTE_GET (ehdr64.e_shstrndx);
    }

  if (filedata->file_header.e_shoff)
    {
      /* There may be some extensions in the first section header.  Don't
	 bomb if we can't read it.  */
      if (is_32bit_elf)
	get_32bit_section_headers (filedata, TRUE);
      else
	get_64bit_section_headers (filedata, TRUE);
    }

  return TRUE;
}



static void parse_args (Filedata * filedata, int argc, char ** argv)
{
  int c;

  if (argc < 2)
    usage (stderr);

  while ((c = getopt_long
	  (argc, argv, "ADHINR:SVWacdeghi:lnp:rstuvw::x:z", options, NULL)) != EOF)
    {
      switch (c)
	{
	case 0:
	  /* Long options.  */
	  break;
	case 'H':
	  usage (stdout);
	  break;

	case 'a':
	  do_syms = TRUE;
	  do_reloc = TRUE;
	  do_unwind = TRUE;
	  do_dynamic = TRUE;
	  do_header = TRUE;
	  do_sections = TRUE;
	  do_section_groups = TRUE;
	  do_segments = TRUE;
	  do_version = TRUE;
	  do_histogram = TRUE;
	  do_arch = TRUE;
	  do_notes = TRUE;
	  break;
	case 'g':
	  do_section_groups = TRUE;
	  break;
	case 't':
	case 'N':
	  do_sections = TRUE;
	  do_section_details = TRUE;
	  break;
	case 'e':
	  do_header = TRUE;
	  do_sections = TRUE;
	  do_segments = TRUE;
	  break;
	case 'A':
	  do_arch = TRUE;
	  break;
	case 'D':
	  do_using_dynamic = TRUE;
	  break;
	case 'r':
	  do_reloc = TRUE;
	  break;
	case 'u':
	  do_unwind = TRUE;
	  break;
	case 'h':
	  do_header = TRUE;
	  break;
	case 'l':
	  do_segments = TRUE;
	  break;
	case 's':
	  do_syms = TRUE;
	  break;
	case 'S':
	  do_sections = TRUE;
	  break;
	case 'd':
	  do_dynamic = TRUE;
	  break;
	case 'I':
	  do_histogram = TRUE;
	  break;
	case 'n':
	  do_notes = TRUE;
	  break;
	case 'c':
	  do_archive_index = TRUE;
	  break;
	case 'x':
	  request_dump (filedata, HEX_DUMP);
	  break;
	case 'p':
	  request_dump (filedata, STRING_DUMP);
	  break;
	case 'R':
	  request_dump (filedata, RELOC_DUMP);
	  break;
	case 'z':
	  decompress_dumps = TRUE;
	  break;
	case 'w':
	  do_dump = TRUE;
	  if (optarg == 0)
	    {
	      do_debugging = TRUE;
	      dwarf_select_sections_all ();
	    }
	  else
	    {
	      do_debugging = FALSE;
	      dwarf_select_sections_by_letters (optarg);
	    }
	  break;
	case OPTION_DEBUG_DUMP:
	  do_dump = TRUE;
	  if (optarg == 0)
	    do_debugging = TRUE;
	  else
	    {
	      do_debugging = FALSE;
	      dwarf_select_sections_by_names (optarg);
	    }
	  break;
	case OPTION_DWARF_DEPTH:
	  {
	    char *cp;

	    dwarf_cutoff_level = strtoul (optarg, & cp, 0);
	  }
	  break;
	case OPTION_DWARF_START:
	  {
	    char *cp;

	    dwarf_start_die = strtoul (optarg, & cp, 0);
	  }
	  break;
	case OPTION_DWARF_CHECK:
	  dwarf_check = TRUE;
	  break;
	case OPTION_CTF_DUMP:
	  do_ctf = TRUE;
	  request_dump (filedata, CTF_DUMP);
	  break;
	case OPTION_CTF_SYMBOLS:
	  dump_ctf_symtab_name = strdup (optarg);
	  break;
	case OPTION_CTF_STRINGS:
	  dump_ctf_strtab_name = strdup (optarg);
	  break;
	case OPTION_CTF_PARENT:
	  dump_ctf_parent_name = strdup (optarg);
	  break;
	case OPTION_DYN_SYMS:
	  do_dyn_syms = TRUE;
	  break;
#ifdef SUPPORT_DISASSEMBLY
	case 'i':
	  request_dump (filedata, DISASS_DUMP);
	  break;
#endif
	case 'v':
	  print_version (program_name);
	  break;
	case 'V':
	  do_version = TRUE;
	  break;
	case 'W':
	  do_wide = TRUE;
	  break;
	default:
	  /* xgettext:c-format */
	  error (_("Invalid option '-%c'\n"), c);
	  /* Fall through.  */
	case '?':
	  usage (stderr);
	}
    }

  if (!do_dynamic && !do_syms && !do_reloc && !do_unwind && !do_sections
      && !do_segments && !do_header && !do_dump && !do_version
      && !do_histogram && !do_debugging && !do_arch && !do_notes
      && !do_section_groups && !do_archive_index
      && !do_dyn_syms)
    usage (stderr);
}


static int
process_file_header ()
{
  if (   elf_header.e_ident [EI_MAG0] != ELFMAG0
      || elf_header.e_ident [EI_MAG1] != ELFMAG1
      || elf_header.e_ident [EI_MAG2] != ELFMAG2
      || elf_header.e_ident [EI_MAG3] != ELFMAG3)
    {
      error
	(_("Not an ELF file - it has the wrong magic bytes at the start\n"));
      return 0;
    }

  if (do_header)
    {
      int i;

      printf (_("ELF Header:\n"));
      printf (_("  Magic:   "));
      for (i = 0; i < EI_NIDENT; i ++)
	printf ("%2.2x ", elf_header.e_ident [i]);
      printf ("\n");
      printf (_("  Class:                             %s\n"),
	      get_elf_class (elf_header.e_ident [EI_CLASS]));
      printf (_("  Data:                              %s\n"),
	      get_data_encoding (elf_header.e_ident [EI_DATA]));
      printf (_("  Version:                           %d %s\n"),
	      elf_header.e_ident [EI_VERSION],
	      (elf_header.e_ident [EI_VERSION] == EV_CURRENT
	       ? "(current)"
	       : (elf_header.e_ident [EI_VERSION] != EV_NONE
		  ? "<unknown: %lx>"
		  : "")));
      printf (_("  OS/ABI:                            %s\n"),
	      get_osabi_name (elf_header.e_ident [EI_OSABI]));
      printf (_("  ABI Version:                       %d\n"),
	      elf_header.e_ident [EI_ABIVERSION]);
      printf (_("  Type:                              %s\n"),
	      get_file_type (elf_header.e_type));
      printf (_("  Machine:                           %s\n"),
	      get_machine_name (elf_header.e_machine));
      printf (_("  Version:                           0x%lx\n"),
	      (unsigned long) elf_header.e_version);

      printf (_("  Entry point address:               "));
      print_vma ((bfd_vma) elf_header.e_entry, PREFIX_HEX);
      printf (_("\n  Start of program headers:          "));
      print_vma ((bfd_vma) elf_header.e_phoff, DEC);
      printf (_(" (bytes into file)\n  Start of section headers:          "));
      print_vma ((bfd_vma) elf_header.e_shoff, DEC);
      printf (_(" (bytes into file)\n"));

      printf (_("  Flags:                             0x%lx%s\n"),
	      (unsigned long) elf_header.e_flags,
	      get_machine_flags (elf_header.e_flags, elf_header.e_machine));
      printf (_("  Size of this header:               %ld (bytes)\n"),
	      (long) elf_header.e_ehsize);
      printf (_("  Size of program headers:           %ld (bytes)\n"),
	      (long) elf_header.e_phentsize);
      printf (_("  Number of program headers:         %ld\n"),
	      (long) elf_header.e_phnum);
      printf (_("  Size of section headers:           %ld (bytes)\n"),
	      (long) elf_header.e_shentsize);
      printf (_("  Number of section headers:         %ld"),
	      (long) elf_header.e_shnum);
      if (section_headers != NULL && elf_header.e_shnum == 0)
	printf (" (%ld)", (long) section_headers[0].sh_size);
      putc ('\n', stdout);
      printf (_("  Section header string table index: %ld"),
	      (long) elf_header.e_shstrndx);
      if (section_headers != NULL && elf_header.e_shstrndx == SHN_XINDEX)
	printf (" (%ld)", (long) section_headers[0].sh_link);
      putc ('\n', stdout);
    }

  if (section_headers != NULL)
    {
      if (elf_header.e_shnum == 0)
	elf_header.e_shnum = section_headers[0].sh_size;
      if (elf_header.e_shstrndx == SHN_XINDEX)
	elf_header.e_shstrndx = section_headers[0].sh_link;
      free (section_headers);
      section_headers = NULL;
    }

  return 1;
}

static int process_file (char* file_name)
{
  FILE *       file;
  struct stat  statbuf;
  unsigned int i;

  if (stat (file_name, & statbuf) < 0)
    {
      error (_("Cannot stat input file %s.\n"), file_name);
      return 1;
    }

  file = fopen (file_name, "rb");
  if (file == NULL)
    {
      error (_("Input file %s not found.\n"), file_name);
      return 1;
    }

    //如果是ELF文件
    //不是就退出
  if (! get_file_header (file))
    {
      error (_("%s: Failed to read file header\n"), file_name);
      fclose (file);
      return 1;
    }

  /* Initialise per file variables.  */
  //变量初始化
  for (i = NUM_ELEM (version_info); i--;)
    version_info[i] = 0;

//这是解析文件的动态部分所需的信息
//#define DT_JMPREL	23
  for (i = NUM_ELEM (dynamic_info); i--;)
    dynamic_info[i] = 0;

  /* Process the file.  */
  //加载这个文件
  //如何这个文件存在，打印文件名
  if (show_name)
    printf (_("\nFile: %s\n"), file_name);

/* 解码保存在“ elf_header”中的数据。 */
  if (! process_file_header ())
    {
      fclose (file);
      return 1;
    }

//反正是一系列加载操作
//加载段头
  process_section_headers (file);

//加载程序头
  process_program_headers (file);

//解析并显示动态部分的内容
  process_dynamic_segment (file);

//加载重定位
  process_relocs (file);

//用于ARM和C6X展开表。
  process_unwind (file);

//转储符号表
  process_symbol_table (file);
  process_syminfo (file);


//显示版本部分的内容。 
  process_version_sections (file);

//为所有请求转储的部分设置DUMP_SECTS
//根据部分名称。
  process_section_contents (file);

//加载codefile
  process_corefile_contents (file);
//加载动态库列表
  process_gnu_liblist (file);
//不知道这是啥
  process_arch_specific (file);

  fclose (file);

//如果section头为真，初始化
  if (section_headers)
    {
      free (section_headers);
      section_headers = NULL;
    }
//如果字符表为真，初始化
  if (string_table)
    {
      free (string_table);
      string_table = NULL;
      string_table_length = 0;
    }

//char *			dynamic_strings;
  if (dynamic_strings)
    {
      free (dynamic_strings);
      dynamic_strings = NULL;
    }

//Elf_Internal_Sym *	dynamic_symbols;
  if (dynamic_symbols)
    {
      free (dynamic_symbols);
      dynamic_symbols = NULL;
      num_dynamic_syms = 0;
    }

//Elf_Internal_Syminfo *	dynamic_syminfo;
  if (dynamic_syminfo)
    {
      free (dynamic_syminfo);
      dynamic_syminfo = NULL;
    }

  return 0;
}


int main (int argc,char** argv)
{
  int err;
  //定义是否具有setlocale函数（地域设置）
  //定义您的locale.h文件是否包含LC_MESSAGES
#if defined (HAVE_SETLOCALE) && defined (HAVE_LC_MESSAGES)
  setlocale (LC_MESSAGES, "");
#endif
#if defined (HAVE_SETLOCALE)
  setlocale (LC_CTYPE, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  parse_args (argc, argv);

    /*1003.2表示必须在任何调用前为1。 */ 
    //int optind = 1;
  if (optind < (argc - 1))
    show_name = 1;

  err = 0;

  while (optind < argc)
    err |= process_file (argv [optind ++]);

  if (dump_sects != NULL)
    free (dump_sects);

  return err;
}