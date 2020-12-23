#include <stdio.h>
#include <linux/elf.h>
#include <bfd.h>
#include <getopt.h>


static bfd_boolean process_section_headers (Filedata * filedata)
{
  Elf_Internal_Shdr * section;
  unsigned int i;

  filedata->section_headers = NULL;

  if (filedata->file_header.e_shnum == 0)
    {
      /* PR binutils/12467.  */
      if (filedata->file_header.e_shoff != 0)
	{
	  warn (_("possibly corrupt ELF file header - it has a non-zero"
		  " section header offset, but no section headers\n"));
	  return FALSE;
	}
      else if (do_sections)
	printf (_("\nThere are no sections in this file.\n"));

      return TRUE;
    }

  if (do_sections && !do_header)
    printf (ngettext ("There is %d section header, "
		      "starting at offset 0x%lx:\n",
		      "There are %d section headers, "
		      "starting at offset 0x%lx:\n",
		      filedata->file_header.e_shnum),
	    filedata->file_header.e_shnum,
	    (unsigned long) filedata->file_header.e_shoff);

  if (is_32bit_elf)
    {
      if (! get_32bit_section_headers (filedata, FALSE))
	return FALSE;
    }
  else
    {
      if (! get_64bit_section_headers (filedata, FALSE))
	return FALSE;
    }

  /* Read in the string table, so that we have names to display.  */
  if (filedata->file_header.e_shstrndx != SHN_UNDEF
       && filedata->file_header.e_shstrndx < filedata->file_header.e_shnum)
    {
      section = filedata->section_headers + filedata->file_header.e_shstrndx;

      if (section->sh_size != 0)
	{
	  filedata->string_table = (char *) get_data (NULL, filedata, section->sh_offset,
						      1, section->sh_size,
						      _("string table"));

	  filedata->string_table_length = filedata->string_table != NULL ? section->sh_size : 0;
	}
    }

  /* Scan the sections for the dynamic symbol table
     and dynamic string table and debug sections.  */
  dynamic_symbols = NULL;
  dynamic_strings = NULL;
  dynamic_syminfo = NULL;
  symtab_shndx_list = NULL;

  eh_addr_size = is_32bit_elf ? 4 : 8;
  switch (filedata->file_header.e_machine)
    {
    case EM_MIPS:
    case EM_MIPS_RS3_LE:
      /* The 64-bit MIPS EABI uses a combination of 32-bit ELF and 64-bit
	 FDE addresses.  However, the ABI also has a semi-official ILP32
	 variant for which the normal FDE address size rules apply.

	 GCC 4.0 marks EABI64 objects with a dummy .gcc_compiled_longXX
	 section, where XX is the size of longs in bits.  Unfortunately,
	 earlier compilers provided no way of distinguishing ILP32 objects
	 from LP64 objects, so if there's any doubt, we should assume that
	 the official LP64 form is being used.  */
      if ((filedata->file_header.e_flags & EF_MIPS_ABI) == E_MIPS_ABI_EABI64
	  && find_section (filedata, ".gcc_compiled_long32") == NULL)
	eh_addr_size = 8;
      break;

    case EM_H8_300:
    case EM_H8_300H:
      switch (filedata->file_header.e_flags & EF_H8_MACH)
	{
	case E_H8_MACH_H8300:
	case E_H8_MACH_H8300HN:
	case E_H8_MACH_H8300SN:
	case E_H8_MACH_H8300SXN:
	  eh_addr_size = 2;
	  break;
	case E_H8_MACH_H8300H:
	case E_H8_MACH_H8300S:
	case E_H8_MACH_H8300SX:
	  eh_addr_size = 4;
	  break;
	}
      break;

    case EM_M32C_OLD:
    case EM_M32C:
      switch (filedata->file_header.e_flags & EF_M32C_CPU_MASK)
	{
	case EF_M32C_CPU_M16C:
	  eh_addr_size = 2;
	  break;
	}
      break;
    }

#define CHECK_ENTSIZE_VALUES(section, i, size32, size64)		\
  do									\
    {									\
      bfd_size_type expected_entsize = is_32bit_elf ? size32 : size64;	\
      if (section->sh_entsize != expected_entsize)			\
	{								\
	  char buf[40];							\
	  sprintf_vma (buf, section->sh_entsize);			\
	  /* Note: coded this way so that there is a single string for  \
	     translation.  */ \
	  error (_("Section %d has invalid sh_entsize of %s\n"), i, buf); \
	  error (_("(Using the expected size of %u for the rest of this dump)\n"), \
		   (unsigned) expected_entsize);			\
	  section->sh_entsize = expected_entsize;			\
	}								\
    }									\
  while (0)

#define CHECK_ENTSIZE(section, i, type)					\
  CHECK_ENTSIZE_VALUES (section, i, sizeof (Elf32_External_##type),	    \
			sizeof (Elf64_External_##type))

  for (i = 0, section = filedata->section_headers;
       i < filedata->file_header.e_shnum;
       i++, section++)
    {
      char * name = SECTION_NAME (section);

      if (section->sh_type == SHT_DYNSYM)
	{
	  if (dynamic_symbols != NULL)
	    {
	      error (_("File contains multiple dynamic symbol tables\n"));
	      continue;
	    }

	  CHECK_ENTSIZE (section, i, Sym);
	  dynamic_symbols = GET_ELF_SYMBOLS (filedata, section, & num_dynamic_syms);
	}
      else if (section->sh_type == SHT_STRTAB
	       && streq (name, ".dynstr"))
	{
	  if (dynamic_strings != NULL)
	    {
	      error (_("File contains multiple dynamic string tables\n"));
	      continue;
	    }

	  dynamic_strings = (char *) get_data (NULL, filedata, section->sh_offset,
                                               1, section->sh_size,
                                               _("dynamic strings"));
	  dynamic_strings_length = dynamic_strings == NULL ? 0 : section->sh_size;
	}
      else if (section->sh_type == SHT_SYMTAB_SHNDX)
	{
	  elf_section_list * entry = xmalloc (sizeof * entry);

	  entry->hdr = section;
	  entry->next = symtab_shndx_list;
	  symtab_shndx_list = entry;
	}
      else if (section->sh_type == SHT_SYMTAB)
	CHECK_ENTSIZE (section, i, Sym);
      else if (section->sh_type == SHT_GROUP)
	CHECK_ENTSIZE_VALUES (section, i, GRP_ENTRY_SIZE, GRP_ENTRY_SIZE);
      else if (section->sh_type == SHT_REL)
	CHECK_ENTSIZE (section, i, Rel);
      else if (section->sh_type == SHT_RELA)
	CHECK_ENTSIZE (section, i, Rela);
      else if ((do_debugging || do_debug_info || do_debug_abbrevs
		|| do_debug_lines || do_debug_pubnames || do_debug_pubtypes
		|| do_debug_aranges || do_debug_frames || do_debug_macinfo
		|| do_debug_str || do_debug_loc || do_debug_ranges
		|| do_debug_addr || do_debug_cu_index || do_debug_links)
	       && (const_strneq (name, ".debug_")
                   || const_strneq (name, ".zdebug_")))
	{
          if (name[1] == 'z')
            name += sizeof (".zdebug_") - 1;
          else
            name += sizeof (".debug_") - 1;

	  if (do_debugging
	      || (do_debug_info     && const_strneq (name, "info"))
	      || (do_debug_info     && const_strneq (name, "types"))
	      || (do_debug_abbrevs  && const_strneq (name, "abbrev"))
	      || (do_debug_lines    && strcmp (name, "line") == 0)
	      || (do_debug_lines    && const_strneq (name, "line."))
	      || (do_debug_pubnames && const_strneq (name, "pubnames"))
	      || (do_debug_pubtypes && const_strneq (name, "pubtypes"))
	      || (do_debug_pubnames && const_strneq (name, "gnu_pubnames"))
	      || (do_debug_pubtypes && const_strneq (name, "gnu_pubtypes"))
	      || (do_debug_aranges  && const_strneq (name, "aranges"))
	      || (do_debug_ranges   && const_strneq (name, "ranges"))
	      || (do_debug_ranges   && const_strneq (name, "rnglists"))
	      || (do_debug_frames   && const_strneq (name, "frame"))
	      || (do_debug_macinfo  && const_strneq (name, "macinfo"))
	      || (do_debug_macinfo  && const_strneq (name, "macro"))
	      || (do_debug_str      && const_strneq (name, "str"))
	      || (do_debug_loc      && const_strneq (name, "loc"))
	      || (do_debug_loc      && const_strneq (name, "loclists"))
	      || (do_debug_addr     && const_strneq (name, "addr"))
	      || (do_debug_cu_index && const_strneq (name, "cu_index"))
	      || (do_debug_cu_index && const_strneq (name, "tu_index"))
	      )
	    request_dump_bynumber (filedata, i, DEBUG_DUMP);
	}
      /* Linkonce section to be combined with .debug_info at link time.  */
      else if ((do_debugging || do_debug_info)
	       && const_strneq (name, ".gnu.linkonce.wi."))
	request_dump_bynumber (filedata, i, DEBUG_DUMP);
      else if (do_debug_frames && streq (name, ".eh_frame"))
	request_dump_bynumber (filedata, i, DEBUG_DUMP);
      else if (do_gdb_index && (streq (name, ".gdb_index")
				|| streq (name, ".debug_names")))
	request_dump_bynumber (filedata, i, DEBUG_DUMP);
      /* Trace sections for Itanium VMS.  */
      else if ((do_debugging || do_trace_info || do_trace_abbrevs
                || do_trace_aranges)
	       && const_strneq (name, ".trace_"))
	{
          name += sizeof (".trace_") - 1;

	  if (do_debugging
	      || (do_trace_info     && streq (name, "info"))
	      || (do_trace_abbrevs  && streq (name, "abbrev"))
	      || (do_trace_aranges  && streq (name, "aranges"))
	      )
	    request_dump_bynumber (filedata, i, DEBUG_DUMP);
	}
      else if ((do_debugging || do_debug_links)
	       && (const_strneq (name, ".gnu_debuglink")
		   || const_strneq (name, ".gnu_debugaltlink")))
	request_dump_bynumber (filedata, i, DEBUG_DUMP);
    }

  if (! do_sections)
    return TRUE;

  if (filedata->file_header.e_shnum > 1)
    printf (_("\nSection Headers:\n"));
  else
    printf (_("\nSection Header:\n"));

  if (is_32bit_elf)
    {
      if (do_section_details)
	{
	  printf (_("  [Nr] Name\n"));
	  printf (_("       Type            Addr     Off    Size   ES   Lk Inf Al\n"));
	}
      else
	printf
	  (_("  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n"));
    }
  else if (do_wide)
    {
      if (do_section_details)
	{
	  printf (_("  [Nr] Name\n"));
	  printf (_("       Type            Address          Off    Size   ES   Lk Inf Al\n"));
	}
      else
	printf
	  (_("  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n"));
    }
  else
    {
      if (do_section_details)
	{
	  printf (_("  [Nr] Name\n"));
	  printf (_("       Type              Address          Offset            Link\n"));
	  printf (_("       Size              EntSize          Info              Align\n"));
	}
      else
	{
	  printf (_("  [Nr] Name              Type             Address           Offset\n"));
	  printf (_("       Size              EntSize          Flags  Link  Info  Align\n"));
	}
    }

  if (do_section_details)
    printf (_("       Flags\n"));

  for (i = 0, section = filedata->section_headers;
       i < filedata->file_header.e_shnum;
       i++, section++)
    {
      /* Run some sanity checks on the section header.  */

      /* Check the sh_link field.  */
      switch (section->sh_type)
	{
	case SHT_REL:
	case SHT_RELA:
	  if (section->sh_link == 0
	      && (filedata->file_header.e_type == ET_EXEC
		  || filedata->file_header.e_type == ET_DYN))
	    /* A dynamic relocation section where all entries use a
	       zero symbol index need not specify a symtab section.  */
	    break;
	  /* Fall through.  */
	case SHT_SYMTAB_SHNDX:
	case SHT_GROUP:
	case SHT_HASH:
	case SHT_GNU_HASH:
	case SHT_GNU_versym:
	  if (section->sh_link == 0
	      || section->sh_link >= filedata->file_header.e_shnum
	      || (filedata->section_headers[section->sh_link].sh_type != SHT_SYMTAB
		  && filedata->section_headers[section->sh_link].sh_type != SHT_DYNSYM))
	    warn (_("[%2u]: Link field (%u) should index a symtab section.\n"),
		  i, section->sh_link);
	  break;

	case SHT_DYNAMIC:
	case SHT_SYMTAB:
	case SHT_DYNSYM:
	case SHT_GNU_verneed:
	case SHT_GNU_verdef:
	case SHT_GNU_LIBLIST:
	  if (section->sh_link == 0
	      || section->sh_link >= filedata->file_header.e_shnum
	      || filedata->section_headers[section->sh_link].sh_type != SHT_STRTAB)
	    warn (_("[%2u]: Link field (%u) should index a string section.\n"),
		  i, section->sh_link);
	  break;

	case SHT_INIT_ARRAY:
	case SHT_FINI_ARRAY:
	case SHT_PREINIT_ARRAY:
	  if (section->sh_type < SHT_LOOS && section->sh_link != 0)
	    warn (_("[%2u]: Unexpected value (%u) in link field.\n"),
		  i, section->sh_link);
	  break;

	default:
	  /* FIXME: Add support for target specific section types.  */
#if 0 	  /* Currently we do not check other section types as there are too
	     many special cases.  Stab sections for example have a type
	     of SHT_PROGBITS but an sh_link field that links to the .stabstr
	     section.  */
	  if (section->sh_type < SHT_LOOS && section->sh_link != 0)
	    warn (_("[%2u]: Unexpected value (%u) in link field.\n"),
		  i, section->sh_link);
#endif
	  break;
	}

      /* Check the sh_info field.  */
      switch (section->sh_type)
	{
	case SHT_REL:
	case SHT_RELA:
	  if (section->sh_info == 0
	      && (filedata->file_header.e_type == ET_EXEC
		  || filedata->file_header.e_type == ET_DYN))
	    /* Dynamic relocations apply to segments, so they do not
	       need to specify the section they relocate.  */
	    break;
	  if (section->sh_info == 0
	      || section->sh_info >= filedata->file_header.e_shnum
	      || (filedata->section_headers[section->sh_info].sh_type != SHT_PROGBITS
		  && filedata->section_headers[section->sh_info].sh_type != SHT_NOBITS
		  && filedata->section_headers[section->sh_info].sh_type != SHT_NOTE
		  && filedata->section_headers[section->sh_info].sh_type != SHT_INIT_ARRAY
		  && filedata->section_headers[section->sh_info].sh_type != SHT_FINI_ARRAY
		  && filedata->section_headers[section->sh_info].sh_type != SHT_PREINIT_ARRAY
		  /* FIXME: Are other section types valid ?  */
		  && filedata->section_headers[section->sh_info].sh_type < SHT_LOOS))
	    warn (_("[%2u]: Info field (%u) should index a relocatable section.\n"),
		  i, section->sh_info);
	  break;

	case SHT_DYNAMIC:
	case SHT_HASH:
	case SHT_SYMTAB_SHNDX:
	case SHT_INIT_ARRAY:
	case SHT_FINI_ARRAY:
	case SHT_PREINIT_ARRAY:
	  if (section->sh_info != 0)
	    warn (_("[%2u]: Unexpected value (%u) in info field.\n"),
		  i, section->sh_info);
	  break;

	case SHT_GROUP:
	case SHT_SYMTAB:
	case SHT_DYNSYM:
	  /* A symbol index - we assume that it is valid.  */
	  break;

	default:
	  /* FIXME: Add support for target specific section types.  */
	  if (section->sh_type == SHT_NOBITS)
	    /* NOBITS section headers with non-zero sh_info fields can be
	       created when a binary is stripped of everything but its debug
	       information.  The stripped sections have their headers
	       preserved but their types set to SHT_NOBITS.  So do not check
	       this type of section.  */
	    ;
	  else if (section->sh_flags & SHF_INFO_LINK)
	    {
	      if (section->sh_info < 1 || section->sh_info >= filedata->file_header.e_shnum)
		warn (_("[%2u]: Expected link to another section in info field"), i);
	    }
	  else if (section->sh_type < SHT_LOOS
		   && (section->sh_flags & SHF_GNU_MBIND) == 0
		   && section->sh_info != 0)
	    warn (_("[%2u]: Unexpected value (%u) in info field.\n"),
		  i, section->sh_info);
	  break;
	}

      /* Check the sh_size field.  */
      if (section->sh_size > filedata->file_size
	  && section->sh_type != SHT_NOBITS
	  && section->sh_type != SHT_NULL
	  && section->sh_type < SHT_LOOS)
	warn (_("Size of section %u is larger than the entire file!\n"), i);

      printf ("  [%2u] ", i);
      if (do_section_details)
	printf ("%s\n      ", printable_section_name (filedata, section));
      else
	print_symbol (-17, SECTION_NAME (section));

      printf (do_wide ? " %-15s " : " %-15.15s ",
	      get_section_type_name (filedata, section->sh_type));

      if (is_32bit_elf)
	{
	  const char * link_too_big = NULL;

	  print_vma (section->sh_addr, LONG_HEX);

	  printf ( " %6.6lx %6.6lx %2.2lx",
		   (unsigned long) section->sh_offset,
		   (unsigned long) section->sh_size,
		   (unsigned long) section->sh_entsize);

	  if (do_section_details)
	    fputs ("  ", stdout);
	  else
	    printf (" %3s ", get_elf_section_flags (filedata, section->sh_flags));

	  if (section->sh_link >= filedata->file_header.e_shnum)
	    {
	      link_too_big = "";
	      /* The sh_link value is out of range.  Normally this indicates
		 an error but it can have special values in Solaris binaries.  */
	      switch (filedata->file_header.e_machine)
		{
		case EM_386:
		case EM_IAMCU:
        
        //#define EM_X86_64	62	/* AMD x86-64 */
		case EM_X86_64:
		
        case EM_L1OM:
		case EM_K1OM:
		case EM_OLD_SPARCV9:
        
        //#define EM_SPARC32PLUS	18	/* Sun's "v8plus" */
        case EM_SPARC32PLUS:
		//#define EM_SPARCV9	43	/* SPARC v9 64-bit */
        case EM_SPARCV9:

        //#define EM_SPARC	2
		case EM_SPARC:
		  if (section->sh_link == (SHN_BEFORE & 0xffff))
		    link_too_big = "BEFORE";
		  else if (section->sh_link == (SHN_AFTER & 0xffff))
		    link_too_big = "AFTER";
		  break;
		default:
		  break;
		}
	    }

	  if (do_section_details)
	    {
	      if (link_too_big != NULL && * link_too_big)
		printf ("<%s> ", link_too_big);
	      else
		printf ("%2u ", section->sh_link);
	      printf ("%3u %2lu\n", section->sh_info,
		      (unsigned long) section->sh_addralign);
	    }
	  else
	    printf ("%2u %3u %2lu\n",
		    section->sh_link,
		    section->sh_info,
		    (unsigned long) section->sh_addralign);

	  if (link_too_big && ! * link_too_big)
	    warn (_("section %u: sh_link value of %u is larger than the number of sections\n"),
		  i, section->sh_link);
	}
      else if (do_wide)
	{
	  print_vma (section->sh_addr, LONG_HEX);

	  if ((long) section->sh_offset == section->sh_offset)
	    printf (" %6.6lx", (unsigned long) section->sh_offset);
	  else
	    {
	      putchar (' ');
	      print_vma (section->sh_offset, LONG_HEX);
	    }

	  if ((unsigned long) section->sh_size == section->sh_size)
	    printf (" %6.6lx", (unsigned long) section->sh_size);
	  else
	    {
	      putchar (' ');
	      print_vma (section->sh_size, LONG_HEX);
	    }

	  if ((unsigned long) section->sh_entsize == section->sh_entsize)
	    printf (" %2.2lx", (unsigned long) section->sh_entsize);
	  else
	    {
	      putchar (' ');
	      print_vma (section->sh_entsize, LONG_HEX);
	    }

	  if (do_section_details)
	    fputs ("  ", stdout);
	  else
	    printf (" %3s ", get_elf_section_flags (filedata, section->sh_flags));

	  printf ("%2u %3u ", section->sh_link, section->sh_info);

	  if ((unsigned long) section->sh_addralign == section->sh_addralign)
	    printf ("%2lu\n", (unsigned long) section->sh_addralign);
	  else
	    {
	      print_vma (section->sh_addralign, DEC);
	      putchar ('\n');
	    }
	}
      else if (do_section_details)
	{
	  putchar (' ');
	  print_vma (section->sh_addr, LONG_HEX);
	  if ((long) section->sh_offset == section->sh_offset)
	    printf ("  %16.16lx", (unsigned long) section->sh_offset);
	  else
	    {
	      printf ("  ");
	      print_vma (section->sh_offset, LONG_HEX);
	    }
	  printf ("  %u\n       ", section->sh_link);
	  print_vma (section->sh_size, LONG_HEX);
	  putchar (' ');
	  print_vma (section->sh_entsize, LONG_HEX);

	  printf ("  %-16u  %lu\n",
		  section->sh_info,
		  (unsigned long) section->sh_addralign);
	}
      else
	{
	  putchar (' ');
	  print_vma (section->sh_addr, LONG_HEX);
	  if ((long) section->sh_offset == section->sh_offset)
	    printf ("  %8.8lx", (unsigned long) section->sh_offset);
	  else
	    {
	      printf ("  ");
	      print_vma (section->sh_offset, LONG_HEX);
	    }
	  printf ("\n       ");
	  print_vma (section->sh_size, LONG_HEX);
	  printf ("  ");
	  print_vma (section->sh_entsize, LONG_HEX);

	  printf (" %3s ", get_elf_section_flags (filedata, section->sh_flags));

	  printf ("     %2u   %3u     %lu\n",
		  section->sh_link,
		  section->sh_info,
		  (unsigned long) section->sh_addralign);
	}

      if (do_section_details)
	{
	  printf ("       %s\n", get_elf_section_flags (filedata, section->sh_flags));
	  if ((section->sh_flags & SHF_COMPRESSED) != 0)
	    {
	      /* Minimum section size is 12 bytes for 32-bit compression
		 header + 12 bytes for compressed data header.  */
	      unsigned char buf[24];

	      assert (sizeof (buf) >= sizeof (Elf64_External_Chdr));
	      if (get_data (&buf, filedata, section->sh_offset, 1,
			    sizeof (buf), _("compression header")))
		{
		  Elf_Internal_Chdr chdr;

		  (void) get_compression_header (&chdr, buf, sizeof (buf));

		  if (chdr.ch_type == ELFCOMPRESS_ZLIB)
		    printf ("       ZLIB, ");
		  else
		    printf (_("       [<unknown>: 0x%x], "),
			    chdr.ch_type);
		  print_vma (chdr.ch_size, LONG_HEX);
		  printf (", %lu\n", (unsigned long) chdr.ch_addralign);
		}
	    }
	}
    }

  if (!do_section_details)
    {
      /* The ordering of the letters shown here matches the ordering of the
	 corresponding SHF_xxx values, and hence the order in which these
	 letters will be displayed to the user.  */
      printf (_("Key to Flags:\n\
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n\
  L (link order), O (extra OS processing required), G (group), T (TLS),\n\
  C (compressed), x (unknown), o (OS specific), E (exclude),\n  "));
      if (filedata->file_header.e_machine == EM_X86_64
	  || filedata->file_header.e_machine == EM_L1OM
	  || filedata->file_header.e_machine == EM_K1OM)
	printf (_("l (large), "));
      else if (filedata->file_header.e_machine == EM_ARM)
	printf (_("y (purecode), "));
      else if (filedata->file_header.e_machine == EM_PPC)
	printf (_("v (VLE), "));
      printf ("p (processor specific)\n");
    }

  return TRUE;
}



/* Returns TRUE if the program headers were loaded.  */

static bfd_boolean process_program_headers (Filedata * filedata)
{
  Elf_Internal_Phdr * segment;
  unsigned int i;
  Elf_Internal_Phdr * previous_load = NULL;

  dynamic_addr = 0;
  dynamic_size = 0;

  if (filedata->file_header.e_phnum == 0)
    {
      /* PR binutils/12467.  */
      if (filedata->file_header.e_phoff != 0)
	{
	  warn (_("possibly corrupt ELF header - it has a non-zero program"
		  " header offset, but no program headers\n"));
	  return FALSE;
	}
      else if (do_segments)
	printf (_("\nThere are no program headers in this file.\n"));
      return TRUE;
    }

  if (do_segments && !do_header)
    {
      printf (_("\nElf file type is %s\n"), get_file_type (filedata->file_header.e_type));
      printf (_("Entry point 0x%s\n"), bfd_vmatoa ("x", filedata->file_header.e_entry));
      printf (ngettext ("There is %d program header, starting at offset %s\n",
			"There are %d program headers, starting at offset %s\n",
			filedata->file_header.e_phnum),
	      filedata->file_header.e_phnum,
	      bfd_vmatoa ("u", filedata->file_header.e_phoff));
    }

  if (! get_program_headers (filedata))
    return TRUE;

  if (do_segments)
    {
      if (filedata->file_header.e_phnum > 1)
	printf (_("\nProgram Headers:\n"));
      else
	printf (_("\nProgram Headers:\n"));

      if (is_32bit_elf)
	printf
	  (_("  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n"));
      else if (do_wide)
	printf
	  (_("  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n"));
      else
	{
	  printf
	    (_("  Type           Offset             VirtAddr           PhysAddr\n"));
	  printf
	    (_("                 FileSiz            MemSiz              Flags  Align\n"));
	}
    }

  for (i = 0, segment = filedata->program_headers;
       i < filedata->file_header.e_phnum;
       i++, segment++)
    {
      if (do_segments)
	{
	  printf ("  %-14.14s ", get_segment_type (filedata, segment->p_type));

	  if (is_32bit_elf)
	    {
	      printf ("0x%6.6lx ", (unsigned long) segment->p_offset);
	      printf ("0x%8.8lx ", (unsigned long) segment->p_vaddr);
	      printf ("0x%8.8lx ", (unsigned long) segment->p_paddr);
	      printf ("0x%5.5lx ", (unsigned long) segment->p_filesz);
	      printf ("0x%5.5lx ", (unsigned long) segment->p_memsz);
	      printf ("%c%c%c ",
		      (segment->p_flags & PF_R ? 'R' : ' '),
		      (segment->p_flags & PF_W ? 'W' : ' '),
		      (segment->p_flags & PF_X ? 'E' : ' '));
	      printf ("%#lx", (unsigned long) segment->p_align);
	    }
	  else if (do_wide)
	    {
	      if ((unsigned long) segment->p_offset == segment->p_offset)
		printf ("0x%6.6lx ", (unsigned long) segment->p_offset);
	      else
		{
		  print_vma (segment->p_offset, FULL_HEX);
		  putchar (' ');
		}

	      print_vma (segment->p_vaddr, FULL_HEX);
	      putchar (' ');
	      print_vma (segment->p_paddr, FULL_HEX);
	      putchar (' ');

	      if ((unsigned long) segment->p_filesz == segment->p_filesz)
		printf ("0x%6.6lx ", (unsigned long) segment->p_filesz);
	      else
		{
		  print_vma (segment->p_filesz, FULL_HEX);
		  putchar (' ');
		}

	      if ((unsigned long) segment->p_memsz == segment->p_memsz)
		printf ("0x%6.6lx", (unsigned long) segment->p_memsz);
	      else
		{
		  print_vma (segment->p_memsz, FULL_HEX);
		}

	      printf (" %c%c%c ",
		      (segment->p_flags & PF_R ? 'R' : ' '),
		      (segment->p_flags & PF_W ? 'W' : ' '),
		      (segment->p_flags & PF_X ? 'E' : ' '));

	      if ((unsigned long) segment->p_align == segment->p_align)
		printf ("%#lx", (unsigned long) segment->p_align);
	      else
		{
		  print_vma (segment->p_align, PREFIX_HEX);
		}
	    }
	  else
	    {
	      print_vma (segment->p_offset, FULL_HEX);
	      putchar (' ');
	      print_vma (segment->p_vaddr, FULL_HEX);
	      putchar (' ');
	      print_vma (segment->p_paddr, FULL_HEX);
	      printf ("\n                 ");
	      print_vma (segment->p_filesz, FULL_HEX);
	      putchar (' ');
	      print_vma (segment->p_memsz, FULL_HEX);
	      printf ("  %c%c%c    ",
		      (segment->p_flags & PF_R ? 'R' : ' '),
		      (segment->p_flags & PF_W ? 'W' : ' '),
		      (segment->p_flags & PF_X ? 'E' : ' '));
	      print_vma (segment->p_align, PREFIX_HEX);
	    }

	  putc ('\n', stdout);
	}

      switch (segment->p_type)
	{
	case PT_LOAD:
#if 0 /* Do not warn about out of order PT_LOAD segments.  Although officially
	 required by the ELF standard, several programs, including the Linux
	 kernel, make use of non-ordered segments.  */
	  if (previous_load
	      && previous_load->p_vaddr > segment->p_vaddr)
	    error (_("LOAD segments must be sorted in order of increasing VirtAddr\n"));
#endif
	  if (segment->p_memsz < segment->p_filesz)
	    error (_("the segment's file size is larger than its memory size\n"));
	  previous_load = segment;
	  break;

	case PT_PHDR:
	  /* PR 20815 - Verify that the program header is loaded into memory.  */
	  if (i > 0 && previous_load != NULL)
	    error (_("the PHDR segment must occur before any LOAD segment\n"));
	  if (filedata->file_header.e_machine != EM_PARISC)
	    {
	      unsigned int j;

	      for (j = 1; j < filedata->file_header.e_phnum; j++)
		{
		  Elf_Internal_Phdr *load = filedata->program_headers + j;
		  if (load->p_type == PT_LOAD
		      && load->p_offset <= segment->p_offset
		      && (load->p_offset + load->p_filesz
			  >= segment->p_offset + segment->p_filesz)
		      && load->p_vaddr <= segment->p_vaddr
		      && (load->p_vaddr + load->p_filesz
			  >= segment->p_vaddr + segment->p_filesz))
		    break;
		}
	      if (j == filedata->file_header.e_phnum)
		error (_("the PHDR segment is not covered by a LOAD segment\n"));
	    }
	  break;

	case PT_DYNAMIC:
	  if (dynamic_addr)
	    error (_("more than one dynamic segment\n"));

	  /* By default, assume that the .dynamic section is the first
	     section in the DYNAMIC segment.  */
	  dynamic_addr = segment->p_offset;
	  dynamic_size = segment->p_filesz;

	  /* Try to locate the .dynamic section. If there is
	     a section header table, we can easily locate it.  */
	  if (filedata->section_headers != NULL)
	    {
	      Elf_Internal_Shdr * sec;

	      sec = find_section (filedata, ".dynamic");
	      if (sec == NULL || sec->sh_size == 0)
		{
                  /* A corresponding .dynamic section is expected, but on
                     IA-64/OpenVMS it is OK for it to be missing.  */
                  if (!is_ia64_vms (filedata))
                    error (_("no .dynamic section in the dynamic segment\n"));
		  break;
		}

	      if (sec->sh_type == SHT_NOBITS)
		{
		  dynamic_size = 0;
		  break;
		}

	      dynamic_addr = sec->sh_offset;
	      dynamic_size = sec->sh_size;

	      if (dynamic_addr < segment->p_offset
		  || dynamic_addr > segment->p_offset + segment->p_filesz)
		warn (_("the .dynamic section is not contained"
			" within the dynamic segment\n"));
	      else if (dynamic_addr > segment->p_offset)
		warn (_("the .dynamic section is not the first section"
			" in the dynamic segment.\n"));
	    }

	  /* PR binutils/17512: Avoid corrupt dynamic section info in the
	     segment.  Check this after matching against the section headers
	     so we don't warn on debuginfo file (which have NOBITS .dynamic
	     sections).  */
	  if (dynamic_addr > filedata->file_size
	      || dynamic_size > filedata->file_size - dynamic_addr)
	    {
	      error (_("the dynamic segment offset + size exceeds the size of the file\n"));
	      dynamic_addr = dynamic_size = 0;
	    }
	  break;

	case PT_INTERP:
	  if (fseek (filedata->handle, archive_file_offset + (long) segment->p_offset,
		     SEEK_SET))
	    error (_("Unable to find program interpreter name\n"));
	  else
	    {
	      char fmt [32];
	      int ret = snprintf (fmt, sizeof (fmt), "%%%ds", PATH_MAX - 1);

	      if (ret >= (int) sizeof (fmt) || ret < 0)
		error (_("Internal error: failed to create format string to display program interpreter\n"));

	      program_interpreter[0] = 0;
	      if (fscanf (filedata->handle, fmt, program_interpreter) <= 0)
		error (_("Unable to read program interpreter name\n"));

	      if (do_segments)
		printf (_("      [Requesting program interpreter: %s]\n"),
		    program_interpreter);
	    }
	  break;
	}
    }

  if (do_segments
      && filedata->section_headers != NULL
      && filedata->string_table != NULL)
    {
      printf (_("\n Section to Segment mapping:\n"));
      printf (_("  Segment Sections...\n"));

      for (i = 0; i < filedata->file_header.e_phnum; i++)
	{
	  unsigned int j;
	  Elf_Internal_Shdr * section;

	  segment = filedata->program_headers + i;
	  section = filedata->section_headers + 1;

	  printf ("   %2.2d     ", i);

	  for (j = 1; j < filedata->file_header.e_shnum; j++, section++)
	    {
	      if (!ELF_TBSS_SPECIAL (section, segment)
		  && ELF_SECTION_IN_SEGMENT_STRICT (section, segment))
		printf ("%s ", printable_section_name (filedata, section));
	    }

	  putc ('\n',stdout);
	}
    }

  return TRUE;
}



/* Parse and display the contents of the dynamic section.  */

static bfd_boolean process_dynamic_section (Filedata * filedata)
{
  Elf_Internal_Dyn * entry;

  if (dynamic_size == 0)
    {
      if (do_dynamic)
	printf (_("\nThere is no dynamic section in this file.\n"));

      return TRUE;
    }

  if (is_32bit_elf)
    {
      if (! get_32bit_dynamic_section (filedata))
	return FALSE;
    }
  else
    {
      if (! get_64bit_dynamic_section (filedata))
	return FALSE;
    }

  /* Find the appropriate symbol table.  */
  if (dynamic_symbols == NULL)
    {
      for (entry = dynamic_section;
	   entry < dynamic_section + dynamic_nent;
	   ++entry)
	{
	  Elf_Internal_Shdr section;

	  if (entry->d_tag != DT_SYMTAB)
	    continue;

	  dynamic_info[DT_SYMTAB] = entry->d_un.d_val;

	  /* Since we do not know how big the symbol table is,
	     we default to reading in the entire file (!) and
	     processing that.  This is overkill, I know, but it
	     should work.  */
	  section.sh_offset = offset_from_vma (filedata, entry->d_un.d_val, 0);
	  if ((bfd_size_type) section.sh_offset > filedata->file_size)
	    {
	      /* See PR 21379 for a reproducer.  */
	      error (_("Invalid DT_SYMTAB entry: %lx"), (long) section.sh_offset);
	      return FALSE;
	    }

	  if (archive_file_offset != 0)
	    section.sh_size = archive_file_size - section.sh_offset;
	  else
	    section.sh_size = filedata->file_size - section.sh_offset;

	  if (is_32bit_elf)
	    section.sh_entsize = sizeof (Elf32_External_Sym);
	  else
	    section.sh_entsize = sizeof (Elf64_External_Sym);
	  section.sh_name = filedata->string_table_length;

	  if (dynamic_symbols != NULL)
	    {
	      error (_("Multiple dynamic symbol table sections found\n"));
	      free (dynamic_symbols);
	    }
	  dynamic_symbols = GET_ELF_SYMBOLS (filedata, &section, & num_dynamic_syms);
	  if (num_dynamic_syms < 1)
	    {
	      error (_("Unable to determine the number of symbols to load\n"));
	      continue;
	    }
	}
    }

  /* Similarly find a string table.  */
  if (dynamic_strings == NULL)
    {
      for (entry = dynamic_section;
	   entry < dynamic_section + dynamic_nent;
	   ++entry)
	{
	  unsigned long offset;
	  long str_tab_len;

	  if (entry->d_tag != DT_STRTAB)
	    continue;

	  dynamic_info[DT_STRTAB] = entry->d_un.d_val;

	  /* Since we do not know how big the string table is,
	     we default to reading in the entire file (!) and
	     processing that.  This is overkill, I know, but it
	     should work.  */

	  offset = offset_from_vma (filedata, entry->d_un.d_val, 0);

	  if (archive_file_offset != 0)
	    str_tab_len = archive_file_size - offset;
	  else
	    str_tab_len = filedata->file_size - offset;

	  if (str_tab_len < 1)
	    {
	      error
		(_("Unable to determine the length of the dynamic string table\n"));
	      continue;
	    }

	  if (dynamic_strings != NULL)
	    {
	      error (_("Multiple dynamic string tables found\n"));
	      free (dynamic_strings);
	    }

	  dynamic_strings = (char *) get_data (NULL, filedata, offset, 1,
                                               str_tab_len,
                                               _("dynamic string table"));
	  dynamic_strings_length = dynamic_strings == NULL ? 0 : str_tab_len;
	}
    }

  /* And find the syminfo section if available.  */
  if (dynamic_syminfo == NULL)
    {
      unsigned long syminsz = 0;

      for (entry = dynamic_section;
	   entry < dynamic_section + dynamic_nent;
	   ++entry)
	{
	  if (entry->d_tag == DT_SYMINENT)
	    {
	      /* Note: these braces are necessary to avoid a syntax
		 error from the SunOS4 C compiler.  */
	      /* PR binutils/17531: A corrupt file can trigger this test.
		 So do not use an assert, instead generate an error message.  */
	      if (sizeof (Elf_External_Syminfo) != entry->d_un.d_val)
		error (_("Bad value (%d) for SYMINENT entry\n"),
		       (int) entry->d_un.d_val);
	    }
	  else if (entry->d_tag == DT_SYMINSZ)
	    syminsz = entry->d_un.d_val;
	  else if (entry->d_tag == DT_SYMINFO)
	    dynamic_syminfo_offset = offset_from_vma (filedata, entry->d_un.d_val,
						      syminsz);
	}

      if (dynamic_syminfo_offset != 0 && syminsz != 0)
	{
	  Elf_External_Syminfo * extsyminfo;
	  Elf_External_Syminfo * extsym;
	  Elf_Internal_Syminfo * syminfo;

	  /* There is a syminfo section.  Read the data.  */
	  extsyminfo = (Elf_External_Syminfo *)
              get_data (NULL, filedata, dynamic_syminfo_offset, 1, syminsz,
                        _("symbol information"));
	  if (!extsyminfo)
	    return FALSE;

	  if (dynamic_syminfo != NULL)
	    {
	      error (_("Multiple dynamic symbol information sections found\n"));
	      free (dynamic_syminfo);
	    }
	  dynamic_syminfo = (Elf_Internal_Syminfo *) malloc (syminsz);
	  if (dynamic_syminfo == NULL)
	    {
	      error (_("Out of memory allocating %lu byte for dynamic symbol info\n"),
		     (unsigned long) syminsz);
	      return FALSE;
	    }

	  dynamic_syminfo_nent = syminsz / sizeof (Elf_External_Syminfo);
	  for (syminfo = dynamic_syminfo, extsym = extsyminfo;
	       syminfo < dynamic_syminfo + dynamic_syminfo_nent;
	       ++syminfo, ++extsym)
	    {
	      syminfo->si_boundto = BYTE_GET (extsym->si_boundto);
	      syminfo->si_flags = BYTE_GET (extsym->si_flags);
	    }

	  free (extsyminfo);
	}
    }

  if (do_dynamic && dynamic_addr)
    printf (ngettext ("\nDynamic section at offset 0x%lx "
		      "contains %lu entry:\n",
		      "\nDynamic section at offset 0x%lx "
		      "contains %lu entries:\n",
		      dynamic_nent),
	    dynamic_addr, (unsigned long) dynamic_nent);
  if (do_dynamic)
    printf (_("  Tag        Type                         Name/Value\n"));

  for (entry = dynamic_section;
       entry < dynamic_section + dynamic_nent;
       entry++)
    {
      if (do_dynamic)
	{
	  const char * dtype;

	  putchar (' ');
	  print_vma (entry->d_tag, FULL_HEX);
	  dtype = get_dynamic_type (filedata, entry->d_tag);
	  printf (" (%s)%*s", dtype,
		  ((is_32bit_elf ? 27 : 19) - (int) strlen (dtype)), " ");
	}

      switch (entry->d_tag)
	{
	case DT_FLAGS:
	  if (do_dynamic)
	    print_dynamic_flags (entry->d_un.d_val);
	  break;

	case DT_AUXILIARY:
	case DT_FILTER:
	case DT_CONFIG:
	case DT_DEPAUDIT:
	case DT_AUDIT:
	  if (do_dynamic)
	    {
	      switch (entry->d_tag)
		{
		case DT_AUXILIARY:
		  printf (_("Auxiliary library"));
		  break;

		case DT_FILTER:
		  printf (_("Filter library"));
		  break;

		case DT_CONFIG:
		  printf (_("Configuration file"));
		  break;

		case DT_DEPAUDIT:
		  printf (_("Dependency audit library"));
		  break;

		case DT_AUDIT:
		  printf (_("Audit library"));
		  break;
		}

	      if (VALID_DYNAMIC_NAME (entry->d_un.d_val))
		printf (": [%s]\n", GET_DYNAMIC_NAME (entry->d_un.d_val));
	      else
		{
		  printf (": ");
		  print_vma (entry->d_un.d_val, PREFIX_HEX);
		  putchar ('\n');
		}
	    }
	  break;

	case DT_FEATURE:
	  if (do_dynamic)
	    {
	      printf (_("Flags:"));

	      if (entry->d_un.d_val == 0)
		printf (_(" None\n"));
	      else
		{
		  unsigned long int val = entry->d_un.d_val;

		  if (val & DTF_1_PARINIT)
		    {
		      printf (" PARINIT");
		      val ^= DTF_1_PARINIT;
		    }
		  if (val & DTF_1_CONFEXP)
		    {
		      printf (" CONFEXP");
		      val ^= DTF_1_CONFEXP;
		    }
		  if (val != 0)
		    printf (" %lx", val);
		  puts ("");
		}
	    }
	  break;

	case DT_POSFLAG_1:
	  if (do_dynamic)
	    {
	      printf (_("Flags:"));

	      if (entry->d_un.d_val == 0)
		printf (_(" None\n"));
	      else
		{
		  unsigned long int val = entry->d_un.d_val;

		  if (val & DF_P1_LAZYLOAD)
		    {
		      printf (" LAZYLOAD");
		      val ^= DF_P1_LAZYLOAD;
		    }
		  if (val & DF_P1_GROUPPERM)
		    {
		      printf (" GROUPPERM");
		      val ^= DF_P1_GROUPPERM;
		    }
		  if (val != 0)
		    printf (" %lx", val);
		  puts ("");
		}
	    }
	  break;

	case DT_FLAGS_1:
	  if (do_dynamic)
	    {
	      printf (_("Flags:"));
	      if (entry->d_un.d_val == 0)
		printf (_(" None\n"));
	      else
		{
		  unsigned long int val = entry->d_un.d_val;

		  if (val & DF_1_NOW)
		    {
		      printf (" NOW");
		      val ^= DF_1_NOW;
		    }
		  if (val & DF_1_GLOBAL)
		    {
		      printf (" GLOBAL");
		      val ^= DF_1_GLOBAL;
		    }
		  if (val & DF_1_GROUP)
		    {
		      printf (" GROUP");
		      val ^= DF_1_GROUP;
		    }
		  if (val & DF_1_NODELETE)
		    {
		      printf (" NODELETE");
		      val ^= DF_1_NODELETE;
		    }
		  if (val & DF_1_LOADFLTR)
		    {
		      printf (" LOADFLTR");
		      val ^= DF_1_LOADFLTR;
		    }
		  if (val & DF_1_INITFIRST)
		    {
		      printf (" INITFIRST");
		      val ^= DF_1_INITFIRST;
		    }
		  if (val & DF_1_NOOPEN)
		    {
		      printf (" NOOPEN");
		      val ^= DF_1_NOOPEN;
		    }
		  if (val & DF_1_ORIGIN)
		    {
		      printf (" ORIGIN");
		      val ^= DF_1_ORIGIN;
		    }
		  if (val & DF_1_DIRECT)
		    {
		      printf (" DIRECT");
		      val ^= DF_1_DIRECT;
		    }
		  if (val & DF_1_TRANS)
		    {
		      printf (" TRANS");
		      val ^= DF_1_TRANS;
		    }
		  if (val & DF_1_INTERPOSE)
		    {
		      printf (" INTERPOSE");
		      val ^= DF_1_INTERPOSE;
		    }
		  if (val & DF_1_NODEFLIB)
		    {
		      printf (" NODEFLIB");
		      val ^= DF_1_NODEFLIB;
		    }
		  if (val & DF_1_NODUMP)
		    {
		      printf (" NODUMP");
		      val ^= DF_1_NODUMP;
		    }
		  if (val & DF_1_CONFALT)
		    {
		      printf (" CONFALT");
		      val ^= DF_1_CONFALT;
		    }
		  if (val & DF_1_ENDFILTEE)
		    {
		      printf (" ENDFILTEE");
		      val ^= DF_1_ENDFILTEE;
		    }
		  if (val & DF_1_DISPRELDNE)
		    {
		      printf (" DISPRELDNE");
		      val ^= DF_1_DISPRELDNE;
		    }
		  if (val & DF_1_DISPRELPND)
		    {
		      printf (" DISPRELPND");
		      val ^= DF_1_DISPRELPND;
		    }
		  if (val & DF_1_NODIRECT)
		    {
		      printf (" NODIRECT");
		      val ^= DF_1_NODIRECT;
		    }
		  if (val & DF_1_IGNMULDEF)
		    {
		      printf (" IGNMULDEF");
		      val ^= DF_1_IGNMULDEF;
		    }
		  if (val & DF_1_NOKSYMS)
		    {
		      printf (" NOKSYMS");
		      val ^= DF_1_NOKSYMS;
		    }
		  if (val & DF_1_NOHDR)
		    {
		      printf (" NOHDR");
		      val ^= DF_1_NOHDR;
		    }
		  if (val & DF_1_EDITED)
		    {
		      printf (" EDITED");
		      val ^= DF_1_EDITED;
		    }
		  if (val & DF_1_NORELOC)
		    {
		      printf (" NORELOC");
		      val ^= DF_1_NORELOC;
		    }
		  if (val & DF_1_SYMINTPOSE)
		    {
		      printf (" SYMINTPOSE");
		      val ^= DF_1_SYMINTPOSE;
		    }
		  if (val & DF_1_GLOBAUDIT)
		    {
		      printf (" GLOBAUDIT");
		      val ^= DF_1_GLOBAUDIT;
		    }
		  if (val & DF_1_SINGLETON)
		    {
		      printf (" SINGLETON");
		      val ^= DF_1_SINGLETON;
		    }
		  if (val & DF_1_STUB)
		    {
		      printf (" STUB");
		      val ^= DF_1_STUB;
		    }
		  if (val & DF_1_PIE)
		    {
		      printf (" PIE");
		      val ^= DF_1_PIE;
		    }
		  if (val & DF_1_KMOD)
		    {
		      printf (" KMOD");
		      val ^= DF_1_KMOD;
		    }
		  if (val & DF_1_WEAKFILTER)
		    {
		      printf (" WEAKFILTER");
		      val ^= DF_1_WEAKFILTER;
		    }
		  if (val & DF_1_NOCOMMON)
		    {
		      printf (" NOCOMMON");
		      val ^= DF_1_NOCOMMON;
		    }
		  if (val != 0)
		    printf (" %lx", val);
		  puts ("");
		}
	    }
	  break;

	case DT_PLTREL:
	  dynamic_info[entry->d_tag] = entry->d_un.d_val;
	  if (do_dynamic)
	    puts (get_dynamic_type (filedata, entry->d_un.d_val));
	  break;

	case DT_NULL	:
	case DT_NEEDED	:
	case DT_PLTGOT	:
	case DT_HASH	:
	case DT_STRTAB	:
	case DT_SYMTAB	:
	case DT_RELA	:
	case DT_INIT	:
	case DT_FINI	:
	case DT_SONAME	:
	case DT_RPATH	:
	case DT_SYMBOLIC:
	case DT_REL	:
	case DT_DEBUG	:
	case DT_TEXTREL	:
	case DT_JMPREL	:
	case DT_RUNPATH	:
	  dynamic_info[entry->d_tag] = entry->d_un.d_val;

	  if (do_dynamic)
	    {
	      char * name;

	      if (VALID_DYNAMIC_NAME (entry->d_un.d_val))
		name = GET_DYNAMIC_NAME (entry->d_un.d_val);
	      else
		name = NULL;

	      if (name)
		{
		  switch (entry->d_tag)
		    {
		    case DT_NEEDED:
		      printf (_("Shared library: [%s]"), name);

		      if (streq (name, program_interpreter))
			printf (_(" program interpreter"));
		      break;

		    case DT_SONAME:
		      printf (_("Library soname: [%s]"), name);
		      break;

		    case DT_RPATH:
		      printf (_("Library rpath: [%s]"), name);
		      break;

		    case DT_RUNPATH:
		      printf (_("Library runpath: [%s]"), name);
		      break;

		    default:
		      print_vma (entry->d_un.d_val, PREFIX_HEX);
		      break;
		    }
		}
	      else
		print_vma (entry->d_un.d_val, PREFIX_HEX);

	      putchar ('\n');
	    }
	  break;

	case DT_PLTRELSZ:
	case DT_RELASZ	:
	case DT_STRSZ	:
	case DT_RELSZ	:
	case DT_RELAENT	:
	case DT_SYMENT	:
	case DT_RELENT	:
	  dynamic_info[entry->d_tag] = entry->d_un.d_val;
	  /* Fall through.  */
	case DT_PLTPADSZ:
	case DT_MOVEENT	:
	case DT_MOVESZ	:
	case DT_INIT_ARRAYSZ:
	case DT_FINI_ARRAYSZ:
	case DT_GNU_CONFLICTSZ:
	case DT_GNU_LIBLISTSZ:
	  if (do_dynamic)
	    {
	      print_vma (entry->d_un.d_val, UNSIGNED);
	      printf (_(" (bytes)\n"));
	    }
	  break;

	case DT_VERDEFNUM:
	case DT_VERNEEDNUM:
	case DT_RELACOUNT:
	case DT_RELCOUNT:
	  if (do_dynamic)
	    {
	      print_vma (entry->d_un.d_val, UNSIGNED);
	      putchar ('\n');
	    }
	  break;

	case DT_SYMINSZ:
	case DT_SYMINENT:
	case DT_SYMINFO:
	case DT_USED:
	case DT_INIT_ARRAY:
	case DT_FINI_ARRAY:
	  if (do_dynamic)
	    {
	      if (entry->d_tag == DT_USED
		  && VALID_DYNAMIC_NAME (entry->d_un.d_val))
		{
		  char * name = GET_DYNAMIC_NAME (entry->d_un.d_val);

		  if (*name)
		    {
		      printf (_("Not needed object: [%s]\n"), name);
		      break;
		    }
		}

	      print_vma (entry->d_un.d_val, PREFIX_HEX);
	      putchar ('\n');
	    }
	  break;

	case DT_BIND_NOW:
	  /* The value of this entry is ignored.  */
	  if (do_dynamic)
	    putchar ('\n');
	  break;

	case DT_GNU_PRELINKED:
	  if (do_dynamic)
	    {
	      struct tm * tmp;
	      time_t atime = entry->d_un.d_val;

	      tmp = gmtime (&atime);
	      /* PR 17533 file: 041-1244816-0.004.  */
	      if (tmp == NULL)
		printf (_("<corrupt time val: %lx"),
			(unsigned long) atime);
	      else
		printf ("%04u-%02u-%02uT%02u:%02u:%02u\n",
			tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
			tmp->tm_hour, tmp->tm_min, tmp->tm_sec);

	    }
	  break;

	case DT_GNU_HASH:
	  dynamic_info_DT_GNU_HASH = entry->d_un.d_val;
	  if (do_dynamic)
	    {
	      print_vma (entry->d_un.d_val, PREFIX_HEX);
	      putchar ('\n');
	    }
	  break;

	default:
	  if ((entry->d_tag >= DT_VERSYM) && (entry->d_tag <= DT_VERNEEDNUM))
	    version_info[DT_VERSIONTAGIDX (entry->d_tag)] =
	      entry->d_un.d_val;

	  if (do_dynamic)
	    {
	      switch (filedata->file_header.e_machine)
		{
		case EM_AARCH64:
		  dynamic_section_aarch64_val (entry);
		  break;
		case EM_MIPS:
		case EM_MIPS_RS3_LE:
		  dynamic_section_mips_val (entry);
		  break;
		case EM_PARISC:
		  dynamic_section_parisc_val (entry);
		  break;
		case EM_IA_64:
		  dynamic_section_ia64_val (entry);
		  break;
		default:
		  print_vma (entry->d_un.d_val, PREFIX_HEX);
		  putchar ('\n');
		}
	    }
	  break;
	}
    }

  return TRUE;
}

/* Process the reloc section.  */

static bfd_boolean process_relocs (Filedata * filedata)
{
  unsigned long rel_size;
  unsigned long rel_offset;

  if (!do_reloc)
    return TRUE;

  if (do_using_dynamic)
    {
      int          is_rela;
      const char * name;
      bfd_boolean  has_dynamic_reloc;
      unsigned int i;

      has_dynamic_reloc = FALSE;

      for (i = 0; i < ARRAY_SIZE (dynamic_relocations); i++)
	{
	  is_rela = dynamic_relocations [i].rela;
	  name = dynamic_relocations [i].name;
	  rel_size = dynamic_info [dynamic_relocations [i].size];
	  rel_offset = dynamic_info [dynamic_relocations [i].reloc];

	  if (rel_size)
	    has_dynamic_reloc = TRUE;

	  if (is_rela == UNKNOWN)
	    {
	      if (dynamic_relocations [i].reloc == DT_JMPREL)
		switch (dynamic_info[DT_PLTREL])
		  {
		  case DT_REL:
		    is_rela = FALSE;
		    break;
		  case DT_RELA:
		    is_rela = TRUE;
		    break;
		  }
	    }

	  if (rel_size)
	    {
	      printf
		(_("\n'%s' relocation section at offset 0x%lx contains %ld bytes:\n"),
		 name, rel_offset, rel_size);

	      dump_relocations (filedata,
				offset_from_vma (filedata, rel_offset, rel_size),
				rel_size,
				dynamic_symbols, num_dynamic_syms,
				dynamic_strings, dynamic_strings_length,
				is_rela, TRUE /* is_dynamic */);
	    }
	}

      if (is_ia64_vms (filedata))
        if (process_ia64_vms_dynamic_relocs (filedata))
	  has_dynamic_reloc = TRUE;

      if (! has_dynamic_reloc)
	printf (_("\nThere are no dynamic relocations in this file.\n"));
    }
  else
    {
      Elf_Internal_Shdr * section;
      unsigned long i;
      bfd_boolean found = FALSE;

      for (i = 0, section = filedata->section_headers;
	   i < filedata->file_header.e_shnum;
	   i++, section++)
	{
	  if (   section->sh_type != SHT_RELA
	      && section->sh_type != SHT_REL)
	    continue;

	  rel_offset = section->sh_offset;
	  rel_size   = section->sh_size;

	  if (rel_size)
	    {
	      Elf_Internal_Shdr * strsec;
	      int is_rela;
	      unsigned long num_rela;

	      printf (_("\nRelocation section "));

	      if (filedata->string_table == NULL)
		printf ("%d", section->sh_name);
	      else
		printf ("'%s'", printable_section_name (filedata, section));

	      num_rela = rel_size / section->sh_entsize;
	      printf (ngettext (" at offset 0x%lx contains %lu entry:\n",
				" at offset 0x%lx contains %lu entries:\n",
				num_rela),
		      rel_offset, num_rela);

	      is_rela = section->sh_type == SHT_RELA;

	      if (section->sh_link != 0
		  && section->sh_link < filedata->file_header.e_shnum)
		{
		  Elf_Internal_Shdr * symsec;
		  Elf_Internal_Sym *  symtab;
		  unsigned long nsyms;
		  unsigned long strtablen = 0;
		  char * strtab = NULL;

		  symsec = filedata->section_headers + section->sh_link;
		  if (symsec->sh_type != SHT_SYMTAB
		      && symsec->sh_type != SHT_DYNSYM)
                    continue;

		  symtab = GET_ELF_SYMBOLS (filedata, symsec, & nsyms);

		  if (symtab == NULL)
		    continue;

		  if (symsec->sh_link != 0
		      && symsec->sh_link < filedata->file_header.e_shnum)
		    {
		      strsec = filedata->section_headers + symsec->sh_link;

		      strtab = (char *) get_data (NULL, filedata, strsec->sh_offset,
						  1, strsec->sh_size,
						  _("string table"));
		      strtablen = strtab == NULL ? 0 : strsec->sh_size;
		    }

		  dump_relocations (filedata, rel_offset, rel_size,
				    symtab, nsyms, strtab, strtablen,
				    is_rela,
				    symsec->sh_type == SHT_DYNSYM);
		  if (strtab)
		    free (strtab);
		  free (symtab);
		}
	      else
		dump_relocations (filedata, rel_offset, rel_size,
				  NULL, 0, NULL, 0, is_rela,
				  FALSE /* is_dynamic */);

	      found = TRUE;
	    }
	}

      if (! found)
	{
	  /* Users sometimes forget the -D option, so try to be helpful.  */
	  for (i = 0; i < ARRAY_SIZE (dynamic_relocations); i++)
	    {
	      if (dynamic_info [dynamic_relocations [i].size])
		{
		  printf (_("\nThere are no static relocations in this file."));
		  printf (_("\nTo see the dynamic relocations add --use-dynamic to the command line.\n"));

		  break;
		}
	    }
	  if (i == ARRAY_SIZE (dynamic_relocations))
	    printf (_("\nThere are no relocations in this file.\n"));
	}
    }

  return TRUE;
}

/* Dump the symbol table.  */
static bfd_boolean
process_symbol_table (Filedata * filedata)
{
  Elf_Internal_Shdr * section;
  bfd_size_type nbuckets = 0;
  bfd_size_type nchains = 0;
  bfd_vma * buckets = NULL;
  bfd_vma * chains = NULL;
  bfd_vma ngnubuckets = 0;
  bfd_vma * gnubuckets = NULL;
  bfd_vma * gnuchains = NULL;
  bfd_vma * mipsxlat = NULL;
  bfd_vma gnusymidx = 0;
  bfd_size_type ngnuchains = 0;

  if (!do_syms && !do_dyn_syms && !do_histogram)
    return TRUE;

  if (dynamic_info[DT_HASH]
      && (do_histogram
	  || (do_using_dynamic
	      && !do_dyn_syms
	      && dynamic_strings != NULL)))
    {
      unsigned char nb[8];
      unsigned char nc[8];
      unsigned int hash_ent_size = 4;

      if ((filedata->file_header.e_machine == EM_ALPHA
	   || filedata->file_header.e_machine == EM_S390
	   || filedata->file_header.e_machine == EM_S390_OLD)
	  && filedata->file_header.e_ident[EI_CLASS] == ELFCLASS64)
	hash_ent_size = 8;

      if (fseek (filedata->handle,
		 (archive_file_offset
		  + offset_from_vma (filedata, dynamic_info[DT_HASH],
				     sizeof nb + sizeof nc)),
		 SEEK_SET))
	{
	  error (_("Unable to seek to start of dynamic information\n"));
	  goto no_hash;
	}

      if (fread (nb, hash_ent_size, 1, filedata->handle) != 1)
	{
	  error (_("Failed to read in number of buckets\n"));
	  goto no_hash;
	}

      if (fread (nc, hash_ent_size, 1, filedata->handle) != 1)
	{
	  error (_("Failed to read in number of chains\n"));
	  goto no_hash;
	}

      nbuckets = byte_get (nb, hash_ent_size);
      nchains  = byte_get (nc, hash_ent_size);

      buckets = get_dynamic_data (filedata, nbuckets, hash_ent_size);
      chains  = get_dynamic_data (filedata, nchains, hash_ent_size);

    no_hash:
      if (buckets == NULL || chains == NULL)
	{
	  if (do_using_dynamic)
	    return FALSE;
	  free (buckets);
	  free (chains);
	  buckets = NULL;
	  chains = NULL;
	  nbuckets = 0;
	  nchains = 0;
	}
    }

  if (dynamic_info_DT_GNU_HASH
      && (do_histogram
	  || (do_using_dynamic
	      && !do_dyn_syms
	      && dynamic_strings != NULL)))
    {
      unsigned char nb[16];
      bfd_vma i, maxchain = 0xffffffff, bitmaskwords;
      bfd_vma buckets_vma;

      if (fseek (filedata->handle,
		 (archive_file_offset
		  + offset_from_vma (filedata, dynamic_info_DT_GNU_HASH,
				     sizeof nb)),
		 SEEK_SET))
	{
	  error (_("Unable to seek to start of dynamic information\n"));
	  goto no_gnu_hash;
	}

      if (fread (nb, 16, 1, filedata->handle) != 1)
	{
	  error (_("Failed to read in number of buckets\n"));
	  goto no_gnu_hash;
	}

      ngnubuckets = byte_get (nb, 4);
      gnusymidx = byte_get (nb + 4, 4);
      bitmaskwords = byte_get (nb + 8, 4);
      buckets_vma = dynamic_info_DT_GNU_HASH + 16;
      if (is_32bit_elf)
	buckets_vma += bitmaskwords * 4;
      else
	buckets_vma += bitmaskwords * 8;

      if (fseek (filedata->handle,
		 (archive_file_offset
		  + offset_from_vma (filedata, buckets_vma, 4)),
		 SEEK_SET))
	{
	  error (_("Unable to seek to start of dynamic information\n"));
	  goto no_gnu_hash;
	}

      gnubuckets = get_dynamic_data (filedata, ngnubuckets, 4);

      if (gnubuckets == NULL)
	goto no_gnu_hash;

      for (i = 0; i < ngnubuckets; i++)
	if (gnubuckets[i] != 0)
	  {
	    if (gnubuckets[i] < gnusymidx)
	      return FALSE;

	    if (maxchain == 0xffffffff || gnubuckets[i] > maxchain)
	      maxchain = gnubuckets[i];
	  }

      if (maxchain == 0xffffffff)
	goto no_gnu_hash;

      maxchain -= gnusymidx;

      if (fseek (filedata->handle,
		 (archive_file_offset
		  + offset_from_vma (filedata, buckets_vma
					   + 4 * (ngnubuckets + maxchain), 4)),
		 SEEK_SET))
	{
	  error (_("Unable to seek to start of dynamic information\n"));
	  goto no_gnu_hash;
	}

      do
	{
	  if (fread (nb, 4, 1, filedata->handle) != 1)
	    {
	      error (_("Failed to determine last chain length\n"));
	      goto no_gnu_hash;
	    }

	  if (maxchain + 1 == 0)
	    goto no_gnu_hash;

	  ++maxchain;
	}
      while ((byte_get (nb, 4) & 1) == 0);

      if (fseek (filedata->handle,
		 (archive_file_offset
		  + offset_from_vma (filedata, buckets_vma + 4 * ngnubuckets, 4)),
		 SEEK_SET))
	{
	  error (_("Unable to seek to start of dynamic information\n"));
	  goto no_gnu_hash;
	}

      gnuchains = get_dynamic_data (filedata, maxchain, 4);
      ngnuchains = maxchain;

      if (gnuchains == NULL)
	goto no_gnu_hash;

      if (dynamic_info_DT_MIPS_XHASH)
	{
	  if (fseek (filedata->handle,
		     (archive_file_offset
		      + offset_from_vma (filedata, (buckets_vma
						    + 4 * (ngnubuckets
							   + maxchain)), 4)),
		     SEEK_SET))
	    {
	      error (_("Unable to seek to start of dynamic information\n"));
	      goto no_gnu_hash;
	    }

	  mipsxlat = get_dynamic_data (filedata, maxchain, 4);
	}

    no_gnu_hash:
      if (dynamic_info_DT_MIPS_XHASH && mipsxlat == NULL)
	{
	  free (gnuchains);
	  gnuchains = NULL;
	}
      if (gnuchains == NULL)
	{
	  free (gnubuckets);
	  gnubuckets = NULL;
	  ngnubuckets = 0;
	  if (do_using_dynamic)
	    return FALSE;
	}
    }

  if ((dynamic_info[DT_HASH] || dynamic_info_DT_GNU_HASH)
      && do_syms
      && do_using_dynamic
      && dynamic_strings != NULL
      && dynamic_symbols != NULL)
    {
      unsigned long hn;

      if (dynamic_info[DT_HASH])
	{
	  bfd_vma si;
	  char *visited;

	  printf (_("\nSymbol table for image:\n"));
	  if (is_32bit_elf)
	    printf (_("  Num Buc:    Value  Size   Type   Bind Vis      Ndx Name\n"));
	  else
	    printf (_("  Num Buc:    Value          Size   Type   Bind Vis      Ndx Name\n"));

	  visited = xcmalloc (nchains, 1);
	  memset (visited, 0, nchains);
	  for (hn = 0; hn < nbuckets; hn++)
	    {
	      for (si = buckets[hn]; si > 0; si = chains[si])
		{
		  print_dynamic_symbol (filedata, si, hn);
		  if (si >= nchains || visited[si])
		    {
		      error (_("histogram chain is corrupt\n"));
		      break;
		    }
		  visited[si] = 1;
		}
	    }
	  free (visited);
	}

      if (dynamic_info_DT_GNU_HASH)
	{
	  printf (_("\nSymbol table of `%s' for image:\n"),
		  GNU_HASH_SECTION_NAME);
	  if (is_32bit_elf)
	    printf (_("  Num Buc:    Value  Size   Type   Bind Vis      Ndx Name\n"));
	  else
	    printf (_("  Num Buc:    Value          Size   Type   Bind Vis      Ndx Name\n"));

	  for (hn = 0; hn < ngnubuckets; ++hn)
	    if (gnubuckets[hn] != 0)
	      {
		bfd_vma si = gnubuckets[hn];
		bfd_vma off = si - gnusymidx;

		do
		  {
		    if (dynamic_info_DT_MIPS_XHASH)
		      print_dynamic_symbol (filedata, mipsxlat[off], hn);
		    else
		      print_dynamic_symbol (filedata, si, hn);
		    si++;
		  }
		while (off < ngnuchains && (gnuchains[off++] & 1) == 0);
	      }
	}
    }
  else if ((do_dyn_syms || (do_syms && !do_using_dynamic))
	   && filedata->section_headers != NULL)
    {
      unsigned int i;

      for (i = 0, section = filedata->section_headers;
	   i < filedata->file_header.e_shnum;
	   i++, section++)
	{
	  unsigned int si;
	  char * strtab = NULL;
	  unsigned long int strtab_size = 0;
	  Elf_Internal_Sym * symtab;
	  Elf_Internal_Sym * psym;
	  unsigned long num_syms;

	  if ((section->sh_type != SHT_SYMTAB
	       && section->sh_type != SHT_DYNSYM)
	      || (!do_syms
		  && section->sh_type == SHT_SYMTAB))
	    continue;

	  if (section->sh_entsize == 0)
	    {
	      printf (_("\nSymbol table '%s' has a sh_entsize of zero!\n"),
		      printable_section_name (filedata, section));
	      continue;
	    }

	  num_syms = section->sh_size / section->sh_entsize;
	  printf (ngettext ("\nSymbol table '%s' contains %lu entry:\n",
			    "\nSymbol table '%s' contains %lu entries:\n",
			    num_syms),
		  printable_section_name (filedata, section),
		  num_syms);

	  if (is_32bit_elf)
	    printf (_("   Num:    Value  Size Type    Bind   Vis      Ndx Name\n"));
	  else
	    printf (_("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"));

	  symtab = GET_ELF_SYMBOLS (filedata, section, & num_syms);
	  if (symtab == NULL)
	    continue;

	  if (section->sh_link == filedata->file_header.e_shstrndx)
	    {
	      strtab = filedata->string_table;
	      strtab_size = filedata->string_table_length;
	    }
	  else if (section->sh_link < filedata->file_header.e_shnum)
	    {
	      Elf_Internal_Shdr * string_sec;

	      string_sec = filedata->section_headers + section->sh_link;

	      strtab = (char *) get_data (NULL, filedata, string_sec->sh_offset,
                                          1, string_sec->sh_size,
                                          _("string table"));
	      strtab_size = strtab != NULL ? string_sec->sh_size : 0;
	    }

	  for (si = 0, psym = symtab; si < num_syms; si++, psym++)
	    {
	      const char *version_string;
	      enum versioned_symbol_info sym_info;
	      unsigned short vna_other;

	      printf ("%6d: ", si);
	      print_vma (psym->st_value, LONG_HEX);
	      putchar (' ');
	      print_vma (psym->st_size, DEC_5);
	      printf (" %-7s", get_symbol_type (filedata, ELF_ST_TYPE (psym->st_info)));
	      printf (" %-6s", get_symbol_binding (filedata, ELF_ST_BIND (psym->st_info)));
	      if (filedata->file_header.e_ident[EI_OSABI] == ELFOSABI_SOLARIS)
		printf (" %-7s",  get_solaris_symbol_visibility (psym->st_other));
	      else
		{
		  unsigned int vis = ELF_ST_VISIBILITY (psym->st_other);

		  printf (" %-7s", get_symbol_visibility (vis));
		  /* Check to see if any other bits in the st_other field are set.
		     Note - displaying this information disrupts the layout of the
		     table being generated, but for the moment this case is very rare.  */
		  if (psym->st_other ^ vis)
		    printf (" [%s] ", get_symbol_other (filedata, psym->st_other ^ vis));
		}
	      printf (" %4s ", get_symbol_index_type (filedata, psym->st_shndx));
	      print_symbol (25, psym->st_name < strtab_size
			    ? strtab + psym->st_name : _("<corrupt>"));

	      version_string
		= get_symbol_version_string (filedata,
					     section->sh_type == SHT_DYNSYM,
					     strtab, strtab_size, si,
					     psym, &sym_info, &vna_other);
	      if (version_string)
		{
		  if (sym_info == symbol_undefined)
		    printf ("@%s (%d)", version_string, vna_other);
		  else
		    printf (sym_info == symbol_hidden ? "@%s" : "@@%s",
			    version_string);
		}

	      putchar ('\n');

	      if (ELF_ST_BIND (psym->st_info) == STB_LOCAL
		  && si >= section->sh_info
		  /* Irix 5 and 6 MIPS binaries are known to ignore this requirement.  */
		  && filedata->file_header.e_machine != EM_MIPS
		  /* Solaris binaries have been found to violate this requirement as
		     well.  Not sure if this is a bug or an ABI requirement.  */
		  && filedata->file_header.e_ident[EI_OSABI] != ELFOSABI_SOLARIS)
		warn (_("local symbol %u found at index >= %s's sh_info value of %u\n"),
		      si, printable_section_name (filedata, section), section->sh_info);
	    }

	  free (symtab);
	  if (strtab != filedata->string_table)
	    free (strtab);
	}
    }
  else if (do_syms)
    printf
      (_("\nDynamic symbol information is not available for displaying symbols.\n"));

  if (do_histogram && buckets != NULL)
    {
      unsigned long * lengths;
      unsigned long * counts;
      unsigned long hn;
      bfd_vma si;
      unsigned long maxlength = 0;
      unsigned long nzero_counts = 0;
      unsigned long nsyms = 0;
      char *visited;

      printf (ngettext ("\nHistogram for bucket list length "
			"(total of %lu bucket):\n",
			"\nHistogram for bucket list length "
			"(total of %lu buckets):\n",
			(unsigned long) nbuckets),
	      (unsigned long) nbuckets);

      lengths = (unsigned long *) calloc (nbuckets, sizeof (*lengths));
      if (lengths == NULL)
	{
	  error (_("Out of memory allocating space for histogram buckets\n"));
	  return FALSE;
	}
      visited = xcmalloc (nchains, 1);
      memset (visited, 0, nchains);

      printf (_(" Length  Number     %% of total  Coverage\n"));
      for (hn = 0; hn < nbuckets; ++hn)
	{
	  for (si = buckets[hn]; si > 0; si = chains[si])
	    {
	      ++nsyms;
	      if (maxlength < ++lengths[hn])
		++maxlength;
	      if (si >= nchains || visited[si])
		{
		  error (_("histogram chain is corrupt\n"));
		  break;
		}
	      visited[si] = 1;
	    }
	}
      free (visited);

      counts = (unsigned long *) calloc (maxlength + 1, sizeof (*counts));
      if (counts == NULL)
	{
	  free (lengths);
	  error (_("Out of memory allocating space for histogram counts\n"));
	  return FALSE;
	}

      for (hn = 0; hn < nbuckets; ++hn)
	++counts[lengths[hn]];

      if (nbuckets > 0)
	{
	  unsigned long i;
	  printf ("      0  %-10lu (%5.1f%%)\n",
		  counts[0], (counts[0] * 100.0) / nbuckets);
	  for (i = 1; i <= maxlength; ++i)
	    {
	      nzero_counts += counts[i] * i;
	      printf ("%7lu  %-10lu (%5.1f%%)    %5.1f%%\n",
		      i, counts[i], (counts[i] * 100.0) / nbuckets,
		      (nzero_counts * 100.0) / nsyms);
	    }
	}

      free (counts);
      free (lengths);
    }

  if (buckets != NULL)
    {
      free (buckets);
      free (chains);
    }

  if (do_histogram && gnubuckets != NULL)
    {
      unsigned long * lengths;
      unsigned long * counts;
      unsigned long hn;
      unsigned long maxlength = 0;
      unsigned long nzero_counts = 0;
      unsigned long nsyms = 0;

      printf (ngettext ("\nHistogram for `%s' bucket list length "
			"(total of %lu bucket):\n",
			"\nHistogram for `%s' bucket list length "
			"(total of %lu buckets):\n",
			(unsigned long) ngnubuckets),
	      GNU_HASH_SECTION_NAME,
	      (unsigned long) ngnubuckets);

      lengths = (unsigned long *) calloc (ngnubuckets, sizeof (*lengths));
      if (lengths == NULL)
	{
	  error (_("Out of memory allocating space for gnu histogram buckets\n"));
	  return FALSE;
	}

      printf (_(" Length  Number     %% of total  Coverage\n"));

      for (hn = 0; hn < ngnubuckets; ++hn)
	if (gnubuckets[hn] != 0)
	  {
	    bfd_vma off, length = 1;

	    for (off = gnubuckets[hn] - gnusymidx;
		 /* PR 17531 file: 010-77222-0.004.  */
		 off < ngnuchains && (gnuchains[off] & 1) == 0;
		 ++off)
	      ++length;
	    lengths[hn] = length;
	    if (length > maxlength)
	      maxlength = length;
	    nsyms += length;
	  }

      counts = (unsigned long *) calloc (maxlength + 1, sizeof (*counts));
      if (counts == NULL)
	{
	  free (lengths);
	  error (_("Out of memory allocating space for gnu histogram counts\n"));
	  return FALSE;
	}

      for (hn = 0; hn < ngnubuckets; ++hn)
	++counts[lengths[hn]];

      if (ngnubuckets > 0)
	{
	  unsigned long j;
	  printf ("      0  %-10lu (%5.1f%%)\n",
		  counts[0], (counts[0] * 100.0) / ngnubuckets);
	  for (j = 1; j <= maxlength; ++j)
	    {
	      nzero_counts += counts[j] * j;
	      printf ("%7lu  %-10lu (%5.1f%%)    %5.1f%%\n",
		      j, counts[j], (counts[j] * 100.0) / ngnubuckets,
		      (nzero_counts * 100.0) / nsyms);
	    }
	}

      free (counts);
      free (lengths);
      free (gnubuckets);
      free (gnuchains);
      free (mipsxlat);
    }

  return TRUE;
}
static bfd_boolean
process_syminfo (Filedata * filedata ATTRIBUTE_UNUSED)
{
  unsigned int i;

  if (dynamic_syminfo == NULL
      || !do_dynamic)
    /* No syminfo, this is ok.  */
    return TRUE;

  /* There better should be a dynamic symbol section.  */
  if (dynamic_symbols == NULL || dynamic_strings == NULL)
    return FALSE;

  if (dynamic_addr)
    printf (ngettext ("\nDynamic info segment at offset 0x%lx "
		      "contains %d entry:\n",
		      "\nDynamic info segment at offset 0x%lx "
		      "contains %d entries:\n",
		      dynamic_syminfo_nent),
	    dynamic_syminfo_offset, dynamic_syminfo_nent);

  printf (_(" Num: Name                           BoundTo     Flags\n"));
  for (i = 0; i < dynamic_syminfo_nent; ++i)
    {
      unsigned short int flags = dynamic_syminfo[i].si_flags;

      printf ("%4d: ", i);
      if (i >= num_dynamic_syms)
	printf (_("<corrupt index>"));
      else if (VALID_DYNAMIC_NAME (dynamic_symbols[i].st_name))
	print_symbol (30, GET_DYNAMIC_NAME (dynamic_symbols[i].st_name));
      else
	printf (_("<corrupt: %19ld>"), dynamic_symbols[i].st_name);
      putchar (' ');

      switch (dynamic_syminfo[i].si_boundto)
	{
	case SYMINFO_BT_SELF:
	  fputs ("SELF       ", stdout);
	  break;
	case SYMINFO_BT_PARENT:
	  fputs ("PARENT     ", stdout);
	  break;
	default:
	  if (dynamic_syminfo[i].si_boundto > 0
	      && dynamic_syminfo[i].si_boundto < dynamic_nent
	      && VALID_DYNAMIC_NAME (dynamic_section[dynamic_syminfo[i].si_boundto].d_un.d_val))
	    {
	      print_symbol (10, GET_DYNAMIC_NAME (dynamic_section[dynamic_syminfo[i].si_boundto].d_un.d_val));
	      putchar (' ' );
	    }
	  else
	    printf ("%-10d ", dynamic_syminfo[i].si_boundto);
	  break;
	}

      if (flags & SYMINFO_FLG_DIRECT)
	printf (" DIRECT");
      if (flags & SYMINFO_FLG_PASSTHRU)
	printf (" PASSTHRU");
      if (flags & SYMINFO_FLG_COPY)
	printf (" COPY");
      if (flags & SYMINFO_FLG_LAZYLOAD)
	printf (" LAZYLOAD");

      puts ("");
    }

  return TRUE;
}


/* Display the contents of the version sections.  */
static bfd_boolean process_version_sections (Filedata * filedata)
{
  Elf_Internal_Shdr * section;
  unsigned i;
  bfd_boolean found = FALSE;

  if (! do_version)
    return TRUE;

  for (i = 0, section = filedata->section_headers;
       i < filedata->file_header.e_shnum;
       i++, section++)
    {
      switch (section->sh_type)
	{
	case SHT_GNU_verdef:
	  {
	    Elf_External_Verdef * edefs;
	    unsigned long idx;
	    unsigned long cnt;
	    char * endbuf;

	    found = TRUE;

	    printf (ngettext ("\nVersion definition section '%s' "
			      "contains %u entry:\n",
			      "\nVersion definition section '%s' "
			      "contains %u entries:\n",
			      section->sh_info),
		    printable_section_name (filedata, section),
		    section->sh_info);

	    printf (_(" Addr: 0x"));
	    printf_vma (section->sh_addr);
	    printf (_("  Offset: %#08lx  Link: %u (%s)\n"),
		    (unsigned long) section->sh_offset, section->sh_link,
		    printable_section_name_from_index (filedata, section->sh_link));

	    edefs = (Elf_External_Verdef *)
                get_data (NULL, filedata, section->sh_offset, 1,section->sh_size,
                          _("version definition section"));
	    if (!edefs)
	      break;
	    endbuf = (char *) edefs + section->sh_size;

	    for (idx = cnt = 0; cnt < section->sh_info; ++cnt)
	      {
		char * vstart;
		Elf_External_Verdef * edef;
		Elf_Internal_Verdef ent;
		Elf_External_Verdaux * eaux;
		Elf_Internal_Verdaux aux;
		unsigned long isum;
		int j;

		vstart = ((char *) edefs) + idx;
		if (vstart + sizeof (*edef) > endbuf)
		  break;

		edef = (Elf_External_Verdef *) vstart;

		ent.vd_version = BYTE_GET (edef->vd_version);
		ent.vd_flags   = BYTE_GET (edef->vd_flags);
		ent.vd_ndx     = BYTE_GET (edef->vd_ndx);
		ent.vd_cnt     = BYTE_GET (edef->vd_cnt);
		ent.vd_hash    = BYTE_GET (edef->vd_hash);
		ent.vd_aux     = BYTE_GET (edef->vd_aux);
		ent.vd_next    = BYTE_GET (edef->vd_next);

		printf (_("  %#06lx: Rev: %d  Flags: %s"),
			idx, ent.vd_version, get_ver_flags (ent.vd_flags));

		printf (_("  Index: %d  Cnt: %d  "),
			ent.vd_ndx, ent.vd_cnt);

		/* Check for overflow.  */
		if (ent.vd_aux > (size_t) (endbuf - vstart))
		  break;

		vstart += ent.vd_aux;

		if (vstart + sizeof (*eaux) > endbuf)
		  break;
		eaux = (Elf_External_Verdaux *) vstart;

		aux.vda_name = BYTE_GET (eaux->vda_name);
		aux.vda_next = BYTE_GET (eaux->vda_next);

		if (VALID_DYNAMIC_NAME (aux.vda_name))
		  printf (_("Name: %s\n"), GET_DYNAMIC_NAME (aux.vda_name));
		else
		  printf (_("Name index: %ld\n"), aux.vda_name);

		isum = idx + ent.vd_aux;

		for (j = 1; j < ent.vd_cnt; j++)
		  {
		    if (aux.vda_next < sizeof (*eaux)
			&& !(j == ent.vd_cnt - 1 && aux.vda_next == 0))
		      {
			warn (_("Invalid vda_next field of %lx\n"),
			      aux.vda_next);
			j = ent.vd_cnt;
			break;
		      }
		    /* Check for overflow.  */
		    if (aux.vda_next > (size_t) (endbuf - vstart))
		      break;

		    isum   += aux.vda_next;
		    vstart += aux.vda_next;

		    if (vstart + sizeof (*eaux) > endbuf)
		      break;
		    eaux = (Elf_External_Verdaux *) vstart;

		    aux.vda_name = BYTE_GET (eaux->vda_name);
		    aux.vda_next = BYTE_GET (eaux->vda_next);

		    if (VALID_DYNAMIC_NAME (aux.vda_name))
		      printf (_("  %#06lx: Parent %d: %s\n"),
			      isum, j, GET_DYNAMIC_NAME (aux.vda_name));
		    else
		      printf (_("  %#06lx: Parent %d, name index: %ld\n"),
			      isum, j, aux.vda_name);
		  }

		if (j < ent.vd_cnt)
		  printf (_("  Version def aux past end of section\n"));

		/* PR 17531:
		   file: id:000001,src:000172+005151,op:splice,rep:2.  */
		if (ent.vd_next < sizeof (*edef)
		    && !(cnt == section->sh_info - 1 && ent.vd_next == 0))
		  {
		    warn (_("Invalid vd_next field of %lx\n"), ent.vd_next);
		    cnt = section->sh_info;
		    break;
		  }
		if (ent.vd_next > (size_t) (endbuf - ((char *) edefs + idx)))
		  break;

		idx += ent.vd_next;
	      }

	    if (cnt < section->sh_info)
	      printf (_("  Version definition past end of section\n"));

	    free (edefs);
	  }
	  break;

	case SHT_GNU_verneed:
	  {
	    Elf_External_Verneed * eneed;
	    unsigned long idx;
	    unsigned long cnt;
	    char * endbuf;

	    found = TRUE;

	    printf (ngettext ("\nVersion needs section '%s' "
			      "contains %u entry:\n",
			      "\nVersion needs section '%s' "
			      "contains %u entries:\n",
			      section->sh_info),
		    printable_section_name (filedata, section), section->sh_info);

	    printf (_(" Addr: 0x"));
	    printf_vma (section->sh_addr);
	    printf (_("  Offset: %#08lx  Link: %u (%s)\n"),
		    (unsigned long) section->sh_offset, section->sh_link,
		    printable_section_name_from_index (filedata, section->sh_link));

	    eneed = (Elf_External_Verneed *) get_data (NULL, filedata,
                                                       section->sh_offset, 1,
                                                       section->sh_size,
                                                       _("Version Needs section"));
	    if (!eneed)
	      break;
	    endbuf = (char *) eneed + section->sh_size;

	    for (idx = cnt = 0; cnt < section->sh_info; ++cnt)
	      {
		Elf_External_Verneed * entry;
		Elf_Internal_Verneed ent;
		unsigned long isum;
		int j;
		char * vstart;

		vstart = ((char *) eneed) + idx;
		if (vstart + sizeof (*entry) > endbuf)
		  break;

		entry = (Elf_External_Verneed *) vstart;

		ent.vn_version = BYTE_GET (entry->vn_version);
		ent.vn_cnt     = BYTE_GET (entry->vn_cnt);
		ent.vn_file    = BYTE_GET (entry->vn_file);
		ent.vn_aux     = BYTE_GET (entry->vn_aux);
		ent.vn_next    = BYTE_GET (entry->vn_next);

		printf (_("  %#06lx: Version: %d"), idx, ent.vn_version);

		if (VALID_DYNAMIC_NAME (ent.vn_file))
		  printf (_("  File: %s"), GET_DYNAMIC_NAME (ent.vn_file));
		else
		  printf (_("  File: %lx"), ent.vn_file);

		printf (_("  Cnt: %d\n"), ent.vn_cnt);

		/* Check for overflow.  */
		if (ent.vn_aux > (size_t) (endbuf - vstart))
		  break;
		vstart += ent.vn_aux;

		for (j = 0, isum = idx + ent.vn_aux; j < ent.vn_cnt; ++j)
		  {
		    Elf_External_Vernaux * eaux;
		    Elf_Internal_Vernaux aux;

		    if (vstart + sizeof (*eaux) > endbuf)
		      break;
		    eaux = (Elf_External_Vernaux *) vstart;

		    aux.vna_hash  = BYTE_GET (eaux->vna_hash);
		    aux.vna_flags = BYTE_GET (eaux->vna_flags);
		    aux.vna_other = BYTE_GET (eaux->vna_other);
		    aux.vna_name  = BYTE_GET (eaux->vna_name);
		    aux.vna_next  = BYTE_GET (eaux->vna_next);

		    if (VALID_DYNAMIC_NAME (aux.vna_name))
		      printf (_("  %#06lx:   Name: %s"),
			      isum, GET_DYNAMIC_NAME (aux.vna_name));
		    else
		      printf (_("  %#06lx:   Name index: %lx"),
			      isum, aux.vna_name);

		    printf (_("  Flags: %s  Version: %d\n"),
			    get_ver_flags (aux.vna_flags), aux.vna_other);

		    if (aux.vna_next < sizeof (*eaux)
			&& !(j == ent.vn_cnt - 1 && aux.vna_next == 0))
		      {
			warn (_("Invalid vna_next field of %lx\n"),
			      aux.vna_next);
			j = ent.vn_cnt;
			break;
		      }
		    /* Check for overflow.  */
		    if (aux.vna_next > (size_t) (endbuf - vstart))
		      break;
		    isum   += aux.vna_next;
		    vstart += aux.vna_next;
		  }

		if (j < ent.vn_cnt)
		  warn (_("Missing Version Needs auxillary information\n"));

		if (ent.vn_next < sizeof (*entry)
		    && !(cnt == section->sh_info - 1 && ent.vn_next == 0))
		  {
		    warn (_("Invalid vn_next field of %lx\n"), ent.vn_next);
		    cnt = section->sh_info;
		    break;
		  }
		if (ent.vn_next > (size_t) (endbuf - ((char *) eneed + idx)))
		  break;
		idx += ent.vn_next;
	      }

	    if (cnt < section->sh_info)
	      warn (_("Missing Version Needs information\n"));

	    free (eneed);
	  }
	  break;

	case SHT_GNU_versym:
	  {
	    Elf_Internal_Shdr * link_section;
	    size_t total;
	    unsigned int cnt;
	    unsigned char * edata;
	    unsigned short * data;
	    char * strtab;
	    Elf_Internal_Sym * symbols;
	    Elf_Internal_Shdr * string_sec;
	    unsigned long num_syms;
	    long off;

	    if (section->sh_link >= filedata->file_header.e_shnum)
	      break;

	    link_section = filedata->section_headers + section->sh_link;
	    total = section->sh_size / sizeof (Elf_External_Versym);

	    if (link_section->sh_link >= filedata->file_header.e_shnum)
	      break;

	    found = TRUE;

	    symbols = GET_ELF_SYMBOLS (filedata, link_section, & num_syms);
	    if (symbols == NULL)
	      break;

	    string_sec = filedata->section_headers + link_section->sh_link;

	    strtab = (char *) get_data (NULL, filedata, string_sec->sh_offset, 1,
                                        string_sec->sh_size,
                                        _("version string table"));
	    if (!strtab)
	      {
		free (symbols);
		break;
	      }

	    printf (ngettext ("\nVersion symbols section '%s' "
			      "contains %lu entry:\n",
			      "\nVersion symbols section '%s' "
			      "contains %lu entries:\n",
			      total),
		    printable_section_name (filedata, section), (unsigned long) total);

	    printf (_(" Addr: 0x"));
	    printf_vma (section->sh_addr);
	    printf (_("  Offset: %#08lx  Link: %u (%s)\n"),
		    (unsigned long) section->sh_offset, section->sh_link,
		    printable_section_name (filedata, link_section));

	    off = offset_from_vma (filedata,
				   version_info[DT_VERSIONTAGIDX (DT_VERSYM)],
				   total * sizeof (short));
	    edata = (unsigned char *) get_data (NULL, filedata, off, total,
                                                sizeof (short),
                                                _("version symbol data"));
	    if (!edata)
	      {
		free (strtab);
		free (symbols);
		break;
	      }

	    data = (short unsigned int *) cmalloc (total, sizeof (short));

	    for (cnt = total; cnt --;)
	      data[cnt] = byte_get (edata + cnt * sizeof (short),
				    sizeof (short));

	    free (edata);

	    for (cnt = 0; cnt < total; cnt += 4)
	      {
		int j, nn;
		char *name;
		char *invalid = _("*invalid*");

		printf ("  %03x:", cnt);

		for (j = 0; (j < 4) && (cnt + j) < total; ++j)
		  switch (data[cnt + j])
		    {
		    case 0:
		      fputs (_("   0 (*local*)    "), stdout);
		      break;

		    case 1:
		      fputs (_("   1 (*global*)   "), stdout);
		      break;

		    default:
		      nn = printf ("%4x%c", data[cnt + j] & VERSYM_VERSION,
				   data[cnt + j] & VERSYM_HIDDEN ? 'h' : ' ');

		      /* If this index value is greater than the size of the symbols
		         array, break to avoid an out-of-bounds read.  */
		      if ((unsigned long)(cnt + j) >= num_syms)
		        {
		          warn (_("invalid index into symbol array\n"));
		          break;
			}

		      name = NULL;
		      if (version_info[DT_VERSIONTAGIDX (DT_VERNEED)])
			{
			  Elf_Internal_Verneed ivn;
			  unsigned long offset;

			  offset = offset_from_vma
			    (filedata, version_info[DT_VERSIONTAGIDX (DT_VERNEED)],
			     sizeof (Elf_External_Verneed));

			  do
			    {
			      Elf_Internal_Vernaux ivna;
			      Elf_External_Verneed evn;
			      Elf_External_Vernaux evna;
			      unsigned long a_off;

			      if (get_data (&evn, filedata, offset, sizeof (evn), 1,
					    _("version need")) == NULL)
				break;

			      ivn.vn_aux  = BYTE_GET (evn.vn_aux);
			      ivn.vn_next = BYTE_GET (evn.vn_next);

			      a_off = offset + ivn.vn_aux;

			      do
				{
				  if (get_data (&evna, filedata, a_off, sizeof (evna),
						1, _("version need aux (2)")) == NULL)
				    {
				      ivna.vna_next  = 0;
				      ivna.vna_other = 0;
				    }
				  else
				    {
				      ivna.vna_next  = BYTE_GET (evna.vna_next);
				      ivna.vna_other = BYTE_GET (evna.vna_other);
				    }

				  a_off += ivna.vna_next;
				}
			      while (ivna.vna_other != data[cnt + j]
				     && ivna.vna_next != 0);

			      if (ivna.vna_other == data[cnt + j])
				{
				  ivna.vna_name = BYTE_GET (evna.vna_name);

				  if (ivna.vna_name >= string_sec->sh_size)
				    name = invalid;
				  else
				    name = strtab + ivna.vna_name;
				  break;
				}

			      offset += ivn.vn_next;
			    }
			  while (ivn.vn_next);
			}

		      if (data[cnt + j] != 0x8001
			  && version_info[DT_VERSIONTAGIDX (DT_VERDEF)])
			{
			  Elf_Internal_Verdef ivd;
			  Elf_External_Verdef evd;
			  unsigned long offset;

			  offset = offset_from_vma
			    (filedata, version_info[DT_VERSIONTAGIDX (DT_VERDEF)],
			     sizeof evd);

			  do
			    {
			      if (get_data (&evd, filedata, offset, sizeof (evd), 1,
					    _("version def")) == NULL)
				{
				  ivd.vd_next = 0;
				  /* PR 17531: file: 046-1082287-0.004.  */
				  ivd.vd_ndx  = (data[cnt + j] & VERSYM_VERSION) + 1;
				  break;
				}
			      else
				{
				  ivd.vd_next = BYTE_GET (evd.vd_next);
				  ivd.vd_ndx  = BYTE_GET (evd.vd_ndx);
				}

			      offset += ivd.vd_next;
			    }
			  while (ivd.vd_ndx != (data[cnt + j] & VERSYM_VERSION)
				 && ivd.vd_next != 0);

			  if (ivd.vd_ndx == (data[cnt + j] & VERSYM_VERSION))
			    {
			      Elf_External_Verdaux evda;
			      Elf_Internal_Verdaux ivda;

			      ivd.vd_aux = BYTE_GET (evd.vd_aux);

			      if (get_data (&evda, filedata,
					    offset - ivd.vd_next + ivd.vd_aux,
					    sizeof (evda), 1,
					    _("version def aux")) == NULL)
				break;

			      ivda.vda_name = BYTE_GET (evda.vda_name);

			      if (ivda.vda_name >= string_sec->sh_size)
				name = invalid;
			      else if (name != NULL && name != invalid)
				name = _("*both*");
			      else
				name = strtab + ivda.vda_name;
			    }
			}
		      if (name != NULL)
			nn += printf ("(%s%-*s",
				      name,
				      12 - (int) strlen (name),
				      ")");

		      if (nn < 18)
			printf ("%*c", 18 - nn, ' ');
		    }

		putchar ('\n');
	      }

	    free (data);
	    free (strtab);
	    free (symbols);
	  }
	  break;

	default:
	  break;
	}
    }

  if (! found)
    printf (_("\nNo version information found in this file.\n"));

  return TRUE;
}


/* Set DUMP_SECTS for all sections where dumps were requested
   based on section name.  */
static bfd_boolean process_section_contents (Filedata * filedata)
{
  Elf_Internal_Shdr * section;
  unsigned int i;
  bfd_boolean res = TRUE;

  if (! do_dump)
    return TRUE;

  initialise_dumps_byname (filedata);

  for (i = 0, section = filedata->section_headers;
       i < filedata->file_header.e_shnum && i < filedata->num_dump_sects;
       i++, section++)
    {
      dump_type dump = filedata->dump_sects[i];

#ifdef SUPPORT_DISASSEMBLY
      if (dump & DISASS_DUMP)
	{
	  if (! disassemble_section (section, filedata))
	    res = FALSE;
	}
#endif
      if (dump & HEX_DUMP)
	{
	  if (! dump_section_as_bytes (section, filedata, FALSE))
	    res = FALSE;
	}

      if (dump & RELOC_DUMP)
	{
	  if (! dump_section_as_bytes (section, filedata, TRUE))
	    res = FALSE;
	}

      if (dump & STRING_DUMP)
	{
	  if (! dump_section_as_strings (section, filedata))
	    res = FALSE;
	}

      if (dump & DEBUG_DUMP)
	{
	  if (! display_debug_section (i, section, filedata))
	    res = FALSE;
	}

      if (dump & CTF_DUMP)
	{
	  if (! dump_section_as_ctf (section, filedata))
	    res = FALSE;
	}
    }

  /* Check to see if the user requested a
     dump of a section that does not exist.  */
  while (i < filedata->num_dump_sects)
    {
      if (filedata->dump_sects[i])
	{
	  warn (_("Section %d was not dumped because it does not exist!\n"), i);
	  res = FALSE;
	}
      i++;
    }

  return res;
}


static bfd_boolean process_corefile_note_segments (Filedata * filedata)
{
  Elf_Internal_Phdr * segment;
  unsigned int i;
  bfd_boolean res = TRUE;

  if (! get_program_headers (filedata))
    return TRUE;

  for (i = 0, segment = filedata->program_headers;
       i < filedata->file_header.e_phnum;
       i++, segment++)
    {
      if (segment->p_type == PT_NOTE)
	if (! process_notes_at (filedata, NULL,
				(bfd_vma) segment->p_offset,
				(bfd_vma) segment->p_filesz,
				(bfd_vma) segment->p_align))
	  res = FALSE;
    }

  return res;
}

static bfd_boolean process_gnu_liblist (Filedata * filedata)
{
  Elf_Internal_Shdr * section;
  Elf_Internal_Shdr * string_sec;
  Elf32_External_Lib * elib;
  char * strtab;
  size_t strtab_size;
  size_t cnt;
  unsigned long num_liblist;
  unsigned i;
  bfd_boolean res = TRUE;

  if (! do_arch)
    return TRUE;

  for (i = 0, section = filedata->section_headers;
       i < filedata->file_header.e_shnum;
       i++, section++)
    {
      switch (section->sh_type)
	{
	case SHT_GNU_LIBLIST:
	  if (section->sh_link >= filedata->file_header.e_shnum)
	    break;

	  elib = (Elf32_External_Lib *)
              get_data (NULL, filedata, section->sh_offset, 1, section->sh_size,
                        _("liblist section data"));

	  if (elib == NULL)
	    {
	      res = FALSE;
	      break;
	    }

	  string_sec = filedata->section_headers + section->sh_link;
	  strtab = (char *) get_data (NULL, filedata, string_sec->sh_offset, 1,
                                      string_sec->sh_size,
                                      _("liblist string table"));
	  if (strtab == NULL
	      || section->sh_entsize != sizeof (Elf32_External_Lib))
	    {
	      free (elib);
	      free (strtab);
	      res = FALSE;
	      break;
	    }
	  strtab_size = string_sec->sh_size;

	  num_liblist = section->sh_size / sizeof (Elf32_External_Lib);
	  printf (ngettext ("\nLibrary list section '%s' contains %lu entries:\n",
			    "\nLibrary list section '%s' contains %lu entries:\n",
			    num_liblist),
		  printable_section_name (filedata, section),
		  num_liblist);

	  puts (_("     Library              Time Stamp          Checksum   Version Flags"));

	  for (cnt = 0; cnt < section->sh_size / sizeof (Elf32_External_Lib);
	       ++cnt)
	    {
	      Elf32_Lib liblist;
	      time_t atime;
	      char timebuf[128];
	      struct tm * tmp;

	      liblist.l_name = BYTE_GET (elib[cnt].l_name);
	      atime = BYTE_GET (elib[cnt].l_time_stamp);
	      liblist.l_checksum = BYTE_GET (elib[cnt].l_checksum);
	      liblist.l_version = BYTE_GET (elib[cnt].l_version);
	      liblist.l_flags = BYTE_GET (elib[cnt].l_flags);

	      tmp = gmtime (&atime);
	      snprintf (timebuf, sizeof (timebuf),
			"%04u-%02u-%02uT%02u:%02u:%02u",
			tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
			tmp->tm_hour, tmp->tm_min, tmp->tm_sec);

	      printf ("%3lu: ", (unsigned long) cnt);
	      if (do_wide)
		printf ("%-20s", liblist.l_name < strtab_size
			? strtab + liblist.l_name : _("<corrupt>"));
	      else
		printf ("%-20.20s", liblist.l_name < strtab_size
			? strtab + liblist.l_name : _("<corrupt>"));
	      printf (" %s %#010lx %-7ld %-7ld\n", timebuf, liblist.l_checksum,
		      liblist.l_version, liblist.l_flags);
	    }

	  free (elib);
	  free (strtab);
	}
    }

  return res;
}

static bfd_boolean process_arch_specific (Filedata * filedata)
{
  if (! do_arch)
    return TRUE;

  switch (filedata->file_header.e_machine)
    {
    case EM_ARC:
    case EM_ARC_COMPACT:
    case EM_ARC_COMPACT2:
      return process_attributes (filedata, "ARC", SHT_ARC_ATTRIBUTES,
				 display_arc_attribute,
				 display_generic_attribute);
    case EM_ARM:
      return process_attributes (filedata, "aeabi", SHT_ARM_ATTRIBUTES,
				 display_arm_attribute,
				 display_generic_attribute);

    case EM_MIPS:
    case EM_MIPS_RS3_LE:
      return process_mips_specific (filedata);

    case EM_MSP430:
     return process_attributes (filedata, "mspabi", SHT_MSP430_ATTRIBUTES,
				display_msp430x_attribute,
				display_msp430_gnu_attribute);

    case EM_RISCV:
     return process_attributes (filedata, "riscv", SHT_RISCV_ATTRIBUTES,
				display_riscv_attribute,
				display_generic_attribute);

    case EM_NDS32:
      return process_nds32_specific (filedata);

    case EM_PPC:
    case EM_PPC64:
      return process_attributes (filedata, NULL, SHT_GNU_ATTRIBUTES, NULL,
				 display_power_gnu_attribute);

    case EM_S390:
    case EM_S390_OLD:
      return process_attributes (filedata, NULL, SHT_GNU_ATTRIBUTES, NULL,
				 display_s390_gnu_attribute);

    case EM_SPARC:
    case EM_SPARC32PLUS:
    case EM_SPARCV9:
      return process_attributes (filedata, NULL, SHT_GNU_ATTRIBUTES, NULL,
				 display_sparc_gnu_attribute);

    case EM_TI_C6000:
      return process_attributes (filedata, "c6xabi", SHT_C6000_ATTRIBUTES,
				 display_tic6x_attribute,
				 display_generic_attribute);

    default:
      return process_attributes (filedata, "gnu", SHT_GNU_ATTRIBUTES,
				 display_public_gnu_attributes,
				 display_generic_attribute);
    }
}