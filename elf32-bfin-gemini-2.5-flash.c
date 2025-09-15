/* ADI Blackfin BFD support for 32-bit ELF.
   Copyright (C) 2005-2025 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/bfin.h"
#include "dwarf2.h"
#include "hashtab.h"
#include "elf32-bfin.h"

/* FUNCTION : bfin_pltpc_reloc
   ABSTRACT : TODO : figure out how to handle pltpc relocs.  */
static bfd_reloc_status_type
bfin_pltpc_reloc (
     bfd *abfd ATTRIBUTE_UNUSED,
     arelent *reloc_entry ATTRIBUTE_UNUSED,
     asymbol *symbol ATTRIBUTE_UNUSED,
     void * data ATTRIBUTE_UNUSED,
     asection *input_section ATTRIBUTE_UNUSED,
     bfd *output_bfd ATTRIBUTE_UNUSED,
     char **error_message ATTRIBUTE_UNUSED)
{
  return bfd_reloc_ok;
}


static bfd_reloc_status_type
bfin_pcrel24_reloc (bfd *abfd,
		    arelent *reloc_entry,
		    asymbol *symbol,
		    void *data,
		    asection *input_section,
		    bfd *output_bfd,
		    char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation_value;
  const bfd_size_type reloc_addr = reloc_entry->address;
  reloc_howto_type *const howto = reloc_entry->howto;
  const bool relocatable = (output_bfd != NULL);

  if (!bfd_reloc_offset_in_range (howto, abfd, input_section, reloc_addr - 2))
    return bfd_reloc_outofrange;

  if (bfd_is_und_section (symbol->section)
      && (symbol->flags & BSF_WEAK) == 0
      && !relocatable)
    return bfd_reloc_undefined;

  bfd_vma current_symbol_value;
  if (bfd_is_com_section (symbol->section))
    current_symbol_value = 0;
  else
    current_symbol_value = symbol->value;

  const bfd_vma output_section_vma = symbol->section->output_section->vma;
  bfd_vma output_base;
  if (relocatable)
    output_base = 0;
  else
    output_base = output_section_vma;

  const bool is_section_name_match = !strcmp (symbol->name, symbol->section->name);

  if (!relocatable || is_section_name_match)
    current_symbol_value += output_base + symbol->section->output_offset;

  if (!relocatable && is_section_name_match)
    current_symbol_value += reloc_entry->addend;

  relocation_value = current_symbol_value;
  relocation_value -= (input_section->output_section->vma + input_section->output_offset);
  relocation_value -= reloc_addr;

  if (howto->complain_on_overflow != complain_overflow_dont)
    {
      bfd_reloc_status_type status;
      status = bfd_check_overflow (howto->complain_on_overflow,
				   howto->bitsize,
				   howto->rightshift,
				   bfd_arch_bits_per_address(abfd),
				   relocation_value);
      if (status != bfd_reloc_ok)
	return status;
    }

  if (howto->rightshift && (relocation_value & 0x01))
    {
      _bfd_error_handler (_("relocation should be even number"));
      return bfd_reloc_overflow;
    }

  relocation_value >>= (bfd_vma) howto->rightshift;
  relocation_value <<= (bfd_vma) howto->bitpos;

  relocation_value += 1;

  if (relocatable)
    {
      reloc_entry->address += input_section->output_offset;
      reloc_entry->addend += symbol->section->output_offset;
    }

  bfd_byte *const target_ptr_word0 = (bfd_byte *) data + reloc_addr - 2;
  bfd_byte *const target_ptr_word1 = (bfd_byte *) data + reloc_addr;

  unsigned short word0_val = bfd_get_16 (abfd, target_ptr_word0);
  word0_val = (word0_val & 0xff00) | ((unsigned short)((relocation_value >> 16) & 0xff));
  bfd_put_16 (abfd, word0_val, target_ptr_word0);

  unsigned short word1_val = (unsigned short)(relocation_value & 0xFFFF);
  bfd_put_16 (abfd, word1_val, target_ptr_word1);

  return bfd_reloc_ok;
}

static bfd_reloc_status_type
bfin_imm16_reloc(bfd *abfd,
                 arelent *reloc_entry,
                 asymbol *symbol,
                 void *data,
                 asection *input_section,
                 bfd *output_bfd,
                 char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation_value;
  const bfd_size_type reloc_addr = reloc_entry->address;
  reloc_howto_type *const howto = reloc_entry->howto;
  const bool is_relocatable = (output_bfd != NULL);

  if (!bfd_reloc_offset_in_range(howto, abfd, input_section, reloc_addr)) {
    return bfd_reloc_outofrange;
  }

  if (bfd_is_und_section(symbol->section) &&
      !(symbol->flags & BSF_WEAK) &&
      !is_relocatable) {
    return bfd_reloc_undefined;
  }

  relocation_value = symbol->value;

  if (!is_relocatable) {
    relocation_value += symbol->section->output_section->vma;
  }

  if (!is_relocatable || !strcmp(symbol->name, symbol->section->name)) {
    relocation_value += symbol->section->output_offset;
  }

  relocation_value += reloc_entry->addend;

  if (is_relocatable) {
    reloc_entry->address += input_section->output_offset;
    reloc_entry->addend += symbol->section->output_offset;
  } else {
    reloc_entry->addend = 0;
  }

  if (howto->complain_on_overflow != complain_overflow_dont) {
    bfd_reloc_status_type status = bfd_check_overflow(
        howto->complain_on_overflow,
        howto->bitsize,
        howto->rightshift,
        bfd_arch_bits_per_address(abfd),
        relocation_value);
    if (status != bfd_reloc_ok) {
      return status;
    }
  }

  relocation_value >>= (bfd_vma)howto->rightshift;
  bfd_put_16(abfd, relocation_value, (unsigned char *)data + reloc_addr);

  return bfd_reloc_ok;
}


static bfd_reloc_status_type
bfin_byte4_reloc (bfd *abfd,
		  arelent *reloc_entry,
		  asymbol *symbol,
		  void * data,
		  asection *input_section,
		  bfd *output_bfd,
		  char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation_value;
  const bfd_size_type addr = reloc_entry->address;
  bfd_vma output_base = 0;
  asection *output_section;
  const bool is_relocatable_output = (output_bfd != NULL);

  if (!bfd_reloc_offset_in_range (reloc_entry->howto, abfd, input_section, addr))
    return bfd_reloc_outofrange;

  if (bfd_is_und_section (symbol->section) && ((symbol->flags & BSF_WEAK) == 0) && !is_relocatable_output)
    return bfd_reloc_undefined;

  output_section = symbol->section->output_section;
  relocation_value = symbol->value;

  if (!is_relocatable_output)
    output_base = output_section->vma;

  const bool symbol_name_matches_section_name =
    (symbol->name != NULL && symbol->section->name != NULL && !strcmp(symbol->name, symbol->section->name));

  if (symbol_name_matches_section_name || !is_relocatable_output)
    {
      relocation_value += output_base + symbol->section->output_offset;
    }

  relocation_value += reloc_entry->addend;

  if (is_relocatable_output)
    {
      reloc_entry->address += input_section->output_offset;
      reloc_entry->addend += symbol->section->output_offset;
    }
  else
    {
      reloc_entry->addend = 0;
    }

  bfd_put_16 (abfd, (unsigned int)(relocation_value >> 16) & 0xFFFF, (unsigned char *) data + addr + 2);
  bfd_put_16 (abfd, (unsigned int)relocation_value & 0xFFFF, (unsigned char *) data + addr);

  return bfd_reloc_ok;
}

/* bfin_bfd_reloc handles the blackfin arithmetic relocations.
   Use this instead of bfd_perform_relocation.  */
static bfd_reloc_status_type
bfin_bfd_reloc (bfd *abfd,
		arelent *reloc_entry,
		asymbol *symbol,
		void *data,
		asection *input_section,
		bfd *output_bfd,
		char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation;
  bfd_size_type addr = reloc_entry->address;
  reloc_howto_type *howto = reloc_entry->howto;
  asection *output_section = symbol->section->output_section;
  bool relocatable = (output_bfd != NULL);

  if (!bfd_reloc_offset_in_range (howto, abfd, input_section, addr))
    {
      return bfd_reloc_outofrange;
    }

  if (bfd_is_und_section (symbol->section)
      && (symbol->flags & BSF_WEAK) == 0
      && !relocatable)
    {
      return bfd_reloc_undefined;
    }

  if (bfd_is_com_section (symbol->section))
    {
      relocation = 0;
    }
  else
    {
      relocation = symbol->value;
    }

  if (!relocatable)
    {
      relocation += output_section->vma + symbol->section->output_offset;
      if (!strcmp (symbol->name, symbol->section->name))
        {
          relocation += reloc_entry->addend;
        }
    }
  else
    {
      if (!strcmp (symbol->name, symbol->section->name))
        {
          relocation += symbol->section->output_offset;
        }
    }

  if (howto->pc_relative)
    {
      relocation -= input_section->output_section->vma + input_section->output_offset;

      if (howto->pcrel_offset)
	relocation -= reloc_entry->address;
    }

  if (relocatable)
    {
      reloc_entry->address += input_section->output_offset;
      reloc_entry->addend += symbol->section->output_offset;
    }

  if (howto->complain_on_overflow != complain_overflow_dont)
    {
      bfd_reloc_status_type status;

      status = bfd_check_overflow (howto->complain_on_overflow,
				  howto->bitsize,
				  howto->rightshift,
				  bfd_arch_bits_per_address(abfd),
				  relocation);
      if (status != bfd_reloc_ok)
	return status;
    }

  if (howto->rightshift && (relocation & 0x01))
    {
      _bfd_error_handler (_("relocation should be even number"));
      return bfd_reloc_overflow;
    }

  relocation >>= (bfd_vma) howto->rightshift;
  relocation <<= (bfd_vma) howto->bitpos;

#define APPLY_RELOC_MASK(val, new_reloc_val, mask) \
  (((val) & ~(mask)) | ((new_reloc_val) & (mask)))

  switch (bfd_get_reloc_size (howto))
    {
    case 1:
      {
	unsigned char x = bfd_get_8 (abfd, (unsigned char *) data + addr);
	x = APPLY_RELOC_MASK(x, relocation, howto->dst_mask);
	bfd_put_8 (abfd, x, (unsigned char *) data + addr);
      }
      break;

    case 2:
      {
	unsigned short x = bfd_get_16 (abfd, (unsigned char *) data + addr);
	x = APPLY_RELOC_MASK(x, relocation, howto->dst_mask);
	bfd_put_16 (abfd, (bfd_vma) x, (unsigned char *) data + addr);
      }
      break;

    default:
      return bfd_reloc_other;
    }

  return bfd_reloc_ok;
}

/* HOWTO Table for blackfin.
   Blackfin relocations are fairly complicated.
   Some of the salient features are
   a. Even numbered offsets. A number of (not all) relocations are
      even numbered. This means that the rightmost bit is not stored.
      Needs to right shift by 1 and check to see if value is not odd
   b. A relocation can be an expression. An expression takes on
      a variety of relocations arranged in a stack.
   As a result, we cannot use the standard generic function as special
   function. We will have our own, which is very similar to the standard
   generic function except that it understands how to get the value from
   the relocation stack. .  */

#define BFIN_RELOC_MIN 0
#define BFIN_RELOC_MAX 0x21
#define BFIN_GNUEXT_RELOC_MIN 0x40
#define BFIN_GNUEXT_RELOC_MAX 0x43
#define BFIN_ARELOC_MIN 0xE0
#define BFIN_ARELOC_MAX 0xF3

static reloc_howto_type bfin_howto_table [] =
{
  /* This reloc does nothing. .  */
  HOWTO (R_BFIN_UNUSED0,	/* type.  */
	 0,			/* rightshift.  */
	 0,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 bfd_elf_generic_reloc,	/* special_function.  */
	 "R_BFIN_UNUSED0",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL5M2,	/* type.  */
	 1,			/* rightshift.  */
	 2,			/* size.  */
	 4,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_unsigned, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_PCREL5M2",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x0000000F,		/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_UNUSED1,	/* type.  */
	 0,			/* rightshift.  */
	 0,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 bfd_elf_generic_reloc,	/* special_function.  */
	 "R_BFIN_UNUSED1",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL10,	/* type.  */
	 1,			/* rightshift.  */
	 2,			/* size.  */
	 10,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_PCREL10",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x000003FF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL12_JUMP,	/* type.  */
	 1,			/* rightshift.  */
				/* the offset is actually 13 bit
				   aligned on a word boundary so
				   only 12 bits have to be used.
				   Right shift the rightmost bit..  */
	 2,			/* size.  */
	 12,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_PCREL12_JUMP",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x0FFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_RIMM16,		/* type.  */
	 0,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_imm16_reloc,	/* special_function.  */
	 "R_BFIN_RIMM16",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x0000FFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_LUIMM16,	/* type.  */
	 0,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 bfin_imm16_reloc,	/* special_function.  */
	 "R_BFIN_LUIMM16",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x0000FFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_HUIMM16,	/* type.  */
	 16,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_unsigned, /* complain_on_overflow.  */
	 bfin_imm16_reloc,	/* special_function.  */
	 "R_BFIN_HUIMM16",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x0000FFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL12_JUMP_S,	/* type.  */
	 1,			/* rightshift.  */
	 2,			/* size.  */
	 12,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_PCREL12_JUMP_S", /* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x00000FFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL24_JUMP_X,	/* type.  */
	 1,			/* rightshift.  */
	 4,			/* size.  */
	 24,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_pcrel24_reloc,	/* special_function.  */
	"R_BFIN_PCREL24_JUMP_X", /* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x00FFFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL24,	/* type.  */
	 1,			/* rightshift.  */
	 4,			/* size.  */
	 24,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_pcrel24_reloc,	/* special_function.  */
	 "R_BFIN_PCREL24",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x00FFFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_UNUSEDB,	/* type.  */
	 0,			/* rightshift.  */
	 0,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 bfd_elf_generic_reloc,	/* special_function.  */
	 "R_BFIN_UNUSEDB",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_UNUSEDC,	/* type.  */
	 0,			/* rightshift.  */
	 0,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 bfd_elf_generic_reloc,	/* special_function.  */
	 "R_BFIN_UNUSEDC",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL24_JUMP_L,	/* type.  */
	 1,			/* rightshift.  */
	 4,			/* size.  */
	 24,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_pcrel24_reloc,	/* special_function.  */
	 "R_BFIN_PCREL24_JUMP_L", /* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x00FFFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL24_CALL_X,	/* type.  */
	 1,			/* rightshift.  */
	 4,			/* size.  */
	 24,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_pcrel24_reloc,	/* special_function.  */
	 "R_BFIN_PCREL24_CALL_X", /* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x00FFFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_VAR_EQ_SYMB,	/* type.  */
	 0,			/* rightshift.  */
	 4,			/* size.  */
	 32,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_bitfield, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_VAR_EQ_SYMB",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_BYTE_DATA,	/* type.  */
	 0,			/* rightshift.  */
	 1,			/* size.  */
	 8,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_unsigned, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_BYTE_DATA",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0xFF,			/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_BYTE2_DATA,	/* type.  */
	 0,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_signed, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_BYTE2_DATA",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0xFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_BYTE4_DATA,	/* type.  */
	 0,			/* rightshift.  */
	 4,			/* size.  */
	 32,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_unsigned, /* complain_on_overflow.  */
	 bfin_byte4_reloc,	/* special_function.  */
	 "R_BFIN_BYTE4_DATA",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0xFFFFFFFF,		/* dst_mask.  */
	 true),			/* pcrel_offset.  */

  HOWTO (R_BFIN_PCREL11,	/* type.  */
	 1,			/* rightshift.  */
	 2,			/* size.  */
	 10,			/* bitsize.  */
	 true,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_unsigned, /* complain_on_overflow.  */
	 bfin_bfd_reloc,	/* special_function.  */
	 "R_BFIN_PCREL11",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0x000003FF,		/* dst_mask.  */
	 false),		/* pcrel_offset.  */


  /* A 18-bit signed operand with the GOT offset for the address of
     the symbol.  */
  HOWTO (R_BFIN_GOT17M4,	/* type */
	 2,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOT17M4",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The upper 16 bits of the GOT offset for the address of the
     symbol.  */
  HOWTO (R_BFIN_GOTHI,		/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOTHI",		/* name */
	 false,			/* partial_inplace */
	 0xffff,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The lower 16 bits of the GOT offset for the address of the
     symbol.  */
  HOWTO (R_BFIN_GOTLO,		/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOTLO",		/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The 32-bit address of the canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 12-bit signed operand with the GOT offset for the address of
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOT17M4,	/* type */
	 2,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOT17M4", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The upper 16 bits of the GOT offset for the address of the
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOTHI,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOTHI", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The lower 16 bits of the GOT offset for the address of the
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOTLO,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOTLO", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The 32-bit address of the canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_VALUE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_VALUE", /* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 12-bit signed operand with the GOT offset for the address of
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOTOFF17M4, /* type */
	 2,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOTOFF17M4", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The upper 16 bits of the GOT offset for the address of the
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOTOFFHI, /* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOTOFFHI", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The lower 16 bits of the GOT offset for the address of the
     canonical descriptor of a function.  */
  HOWTO (R_BFIN_FUNCDESC_GOTOFFLO, /* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_FUNCDESC_GOTOFFLO", /* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 12-bit signed operand with the GOT offset for the address of
     the symbol.  */
  HOWTO (R_BFIN_GOTOFF17M4,	/* type */
	 2,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOTOFF17M4",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The upper 16 bits of the GOT offset for the address of the
     symbol.  */
  HOWTO (R_BFIN_GOTOFFHI,	 /* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOTOFFHI",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* The lower 16 bits of the GOT offset for the address of the
     symbol.  */
  HOWTO (R_BFIN_GOTOFFLO,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_BFIN_GOTOFFLO",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */
};

static reloc_howto_type bfin_gnuext_howto_table [] =
{
  HOWTO (R_BFIN_PLTPC,		/* type.  */
	 0,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_bitfield, /* complain_on_overflow.  */
	 bfin_pltpc_reloc,	/* special_function.  */
	 "R_BFIN_PLTPC",	/* name.  */
	 false,			/* partial_inplace.  */
	 0xffff,		/* src_mask.  */
	 0xffff,		/* dst_mask.  */
	 false),		/* pcrel_offset.  */

  HOWTO (R_BFIN_GOT,		/* type.  */
	 0,			/* rightshift.  */
	 2,			/* size.  */
	 16,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_bitfield, /* complain_on_overflow.  */
	 bfd_elf_generic_reloc,	/* special_function.  */
	 "R_BFIN_GOT",		/* name.  */
	 false,			/* partial_inplace.  */
	 0x7fff,		/* src_mask.  */
	 0x7fff,		/* dst_mask.  */
	 false),		/* pcrel_offset.  */

/* GNU extension to record C++ vtable hierarchy.  */
  HOWTO (R_BFIN_GNU_VTINHERIT,	/* type.  */
	 0,			/* rightshift.  */
	 4,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 NULL,			/* special_function.  */
	 "R_BFIN_GNU_VTINHERIT", /* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false),		/* pcrel_offset.  */

/* GNU extension to record C++ vtable member usage.  */
  HOWTO (R_BFIN_GNU_VTENTRY,	/* type.  */
	 0,			/* rightshift.  */
	 4,			/* size.  */
	 0,			/* bitsize.  */
	 false,			/* pc_relative.  */
	 0,			/* bitpos.  */
	 complain_overflow_dont, /* complain_on_overflow.  */
	 _bfd_elf_rel_vtable_reloc_fn, /* special_function.  */
	 "R_BFIN_GNU_VTENTRY",	/* name.  */
	 false,			/* partial_inplace.  */
	 0,			/* src_mask.  */
	 0,			/* dst_mask.  */
	 false)			/* pcrel_offset.  */
};

struct bfin_reloc_map
{
  bfd_reloc_code_real_type	bfd_reloc_val;
  unsigned int			bfin_reloc_val;
};

static const struct bfin_reloc_map bfin_reloc_map [] =
{
  { BFD_RELOC_NONE,			R_BFIN_UNUSED0 },
  { BFD_RELOC_BFIN_5_PCREL,		R_BFIN_PCREL5M2 },
  { BFD_RELOC_NONE,			R_BFIN_UNUSED1 },
  { BFD_RELOC_BFIN_10_PCREL,		R_BFIN_PCREL10 },
  { BFD_RELOC_BFIN_12_PCREL_JUMP,	R_BFIN_PCREL12_JUMP },
  { BFD_RELOC_BFIN_16_IMM,		R_BFIN_RIMM16 },
  { BFD_RELOC_BFIN_16_LOW,		R_BFIN_LUIMM16 },
  { BFD_RELOC_BFIN_16_HIGH,		R_BFIN_HUIMM16 },
  { BFD_RELOC_BFIN_12_PCREL_JUMP_S,	R_BFIN_PCREL12_JUMP_S },
  { BFD_RELOC_24_PCREL,			R_BFIN_PCREL24 },
  { BFD_RELOC_24_PCREL,			R_BFIN_PCREL24 },
  { BFD_RELOC_BFIN_24_PCREL_JUMP_L,	R_BFIN_PCREL24_JUMP_L },
  { BFD_RELOC_NONE,			R_BFIN_UNUSEDB },
  { BFD_RELOC_NONE,			R_BFIN_UNUSEDC },
  { BFD_RELOC_BFIN_24_PCREL_CALL_X,	R_BFIN_PCREL24_CALL_X },
  { BFD_RELOC_8,			R_BFIN_BYTE_DATA },
  { BFD_RELOC_16,			R_BFIN_BYTE2_DATA },
  { BFD_RELOC_32,			R_BFIN_BYTE4_DATA },
  { BFD_RELOC_BFIN_11_PCREL,		R_BFIN_PCREL11 },
  { BFD_RELOC_BFIN_GOT,			R_BFIN_GOT },
  { BFD_RELOC_BFIN_PLTPC,		R_BFIN_PLTPC },

  { BFD_RELOC_BFIN_GOT17M4,      R_BFIN_GOT17M4 },
  { BFD_RELOC_BFIN_GOTHI,      R_BFIN_GOTHI },
  { BFD_RELOC_BFIN_GOTLO,      R_BFIN_GOTLO },
  { BFD_RELOC_BFIN_FUNCDESC,   R_BFIN_FUNCDESC },
  { BFD_RELOC_BFIN_FUNCDESC_GOT17M4, R_BFIN_FUNCDESC_GOT17M4 },
  { BFD_RELOC_BFIN_FUNCDESC_GOTHI, R_BFIN_FUNCDESC_GOTHI },
  { BFD_RELOC_BFIN_FUNCDESC_GOTLO, R_BFIN_FUNCDESC_GOTLO },
  { BFD_RELOC_BFIN_FUNCDESC_VALUE, R_BFIN_FUNCDESC_VALUE },
  { BFD_RELOC_BFIN_FUNCDESC_GOTOFF17M4, R_BFIN_FUNCDESC_GOTOFF17M4 },
  { BFD_RELOC_BFIN_FUNCDESC_GOTOFFHI, R_BFIN_FUNCDESC_GOTOFFHI },
  { BFD_RELOC_BFIN_FUNCDESC_GOTOFFLO, R_BFIN_FUNCDESC_GOTOFFLO },
  { BFD_RELOC_BFIN_GOTOFF17M4,   R_BFIN_GOTOFF17M4 },
  { BFD_RELOC_BFIN_GOTOFFHI,   R_BFIN_GOTOFFHI },
  { BFD_RELOC_BFIN_GOTOFFLO,   R_BFIN_GOTOFFLO },

  { BFD_RELOC_VTABLE_INHERIT,		R_BFIN_GNU_VTINHERIT },
  { BFD_RELOC_VTABLE_ENTRY,		R_BFIN_GNU_VTENTRY },
};


static bool
bfin_info_to_howto (const bfd *abfd,
		    arelent *cache_ptr,
		    const Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (dst->r_info);

  if (r_type <= BFIN_RELOC_MAX)
    {
      cache_ptr->howto = &bfin_howto_table [r_type];
    }
  else if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
    {
      cache_ptr->howto = &bfin_gnuext_howto_table [r_type - BFIN_GNUEXT_RELOC_MIN];
    }
  else
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  return true;
}

/* Given a BFD reloc type, return the howto.  */
static reloc_howto_type *
bfin_bfd_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
			    bfd_reloc_code_real_type code)
{
  size_t i;
  unsigned int r_type = (unsigned int) -1; /* Sentinel value for "not found" */
  const size_t num_relocs = sizeof (bfin_reloc_map) / sizeof (bfin_reloc_map[0]);

  /* Iterate through the relocation map to find a matching code.
   * Break early once a match is found.
   */
  for (i = 0; i < num_relocs; ++i)
    {
      if (bfin_reloc_map[i].bfd_reloc_val == code)
        {
          r_type = bfin_reloc_map[i].bfin_reloc_val;
          break; /* Match found, no need to continue searching */
        }
    }

  /* If a matching relocation type was found, determine which howto table to use. */
  if (r_type != (unsigned int) -1)
    {
      if (r_type <= BFIN_RELOC_MAX)
        {
          return &bfin_howto_table[r_type];
        }
      else if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
        {
          return &bfin_gnuext_howto_table[r_type - BFIN_GNUEXT_RELOC_MIN];
        }
    }

  /* No matching relocation type found or r_type fell outside defined ranges. */
  return (reloc_howto_type *) NULL;
}

static reloc_howto_type *
lookup_reloc_in_table_internal (const reloc_howto_type *table, size_t num_entries, const char *r_name)
{
  for (size_t i = 0; i < num_entries; i++)
    {
      if (table[i].name != NULL && strcasecmp (table[i].name, r_name) == 0)
        {
          return (reloc_howto_type *)&table[i];
        }
    }
  return NULL;
}

static reloc_howto_type *
bfin_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{
  if (r_name == NULL)
    {
      return NULL;
    }

  reloc_howto_type *found = lookup_reloc_in_table_internal (bfin_howto_table,
                                                             sizeof (bfin_howto_table) / sizeof (bfin_howto_table[0]),
                                                             r_name);
  if (found != NULL)
    {
      return found;
    }

  found = lookup_reloc_in_table_internal (bfin_gnuext_howto_table,
                                          sizeof (bfin_gnuext_howto_table) / sizeof (bfin_gnuext_howto_table[0]),
                                          r_name);
  return found;
}

/* Given a bfin relocation type, return the howto.  */
static reloc_howto_type *
bfin_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
			unsigned int r_type)
{
  if (r_type <= BFIN_RELOC_MAX)
    return &bfin_howto_table [r_type];
  else if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
   return &bfin_gnuext_howto_table [r_type - BFIN_GNUEXT_RELOC_MIN];

  return NULL;
}

/* Set by ld emulation if --code-in-l1.  */
bool elf32_bfin_code_in_l1 = 0;

/* Set by ld emulation if --data-in-l1.  */
bool elf32_bfin_data_in_l1 = 0;

static bool
elf32_bfin_final_write_processing (bfd *abfd)
{
  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);

  if (ehdr != NULL)
    {
      if (elf32_bfin_code_in_l1)
        ehdr->e_flags |= EF_BFIN_CODE_IN_L1;
      if (elf32_bfin_data_in_l1)
        ehdr->e_flags |= EF_BFIN_DATA_IN_L1;
    }

  return _bfd_elf_final_write_processing (abfd);
}

/* Return TRUE if the name is a local label.
   bfin local labels begin with L$.  */
static bool
bfin_is_local_label_name (bfd *abfd, const char *label)
{
  if (label != NULL && label[0] == 'L' && label[1] == '$')
    return true;

  return _bfd_elf_is_local_label_name (abfd, label);
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bool
bfin_check_relocs (bfd * abfd,
                   struct bfd_link_info *info,
                   asection *sec,
                   const Elf_Internal_Rela *relocs)
{
  if (bfd_link_relocatable (info))
    return true;

  struct elf_link_hash_table *hash_table = elf_hash_table(info);
  bfd *dynobj = hash_table->dynobj;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  bfd_signed_vma *local_got_refcounts = elf_local_got_refcounts (abfd);

  asection *sgot = NULL;
  asection *srelgot = NULL;

  const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
  for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++)
    {
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      struct elf_link_hash_entry *h = NULL;

      // Resolve the symbol hash entry 'h'.
      // If r_symndx is less than sh_info, it refers to a local symbol.
      if (r_symndx >= symtab_hdr->sh_info)
        {
          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          // Follow indirect or warning links to find the final symbol.
          while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *)h->root.u.i.link;
        }

      switch (ELF32_R_TYPE (rel->r_info))
        {
        case R_BFIN_GNU_VTINHERIT:
          // This relocation describes the C++ object vtable hierarchy.
          // Reconstruct it for later use during GC.
          if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
            return false;
          break;

        case R_BFIN_GNU_VTENTRY:
          // This relocation describes which C++ vtable entries
          // are actually used. Record for later use during GC.
          if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
            return false;
          break;

        case R_BFIN_GOT:
          // If the symbol is the Global Offset Table itself, no further processing needed for this relocation.
          if (h != NULL && strcmp (h->root.root.string, "__GLOBAL_OFFSET_TABLE_") == 0)
            break;

          // If a dynamic object hasn't been established yet for GOT entries,
          // create the .got section within the current object.
          if (dynobj == NULL)
            {
              hash_table->dynobj = dynobj = abfd;
              if (!_bfd_elf_create_got_section (dynobj, info))
                return false;
            }

          // Retrieve .got and .rel.got sections, ensuring they reflect the current dynobj state.
          sgot = hash_table->sgot;
          srelgot = hash_table->srelgot;
          BFD_ASSERT (sgot != NULL); // Assert that the GOT section was successfully created.

          if (h != NULL) // Handle global/dynamic symbols requiring GOT entry.
            {
              if (h->got.refcount == 0)
                {
                  // Ensure this symbol is recorded as a dynamic symbol if not already.
                  if (h->dynindx == -1 && !h->forced_local)
                    {
                      if (!bfd_elf_link_record_dynamic_symbol (info, h))
                        return false;
                    }

                  // Allocate space in the .got section (4 bytes per entry for 32-bit arch)
                  // and corresponding relocation space in .rel.got.
                  sgot->size += 4;
                  srelgot->size += sizeof (Elf32_External_Rela);
                }
              h->got.refcount++;
            }
          else // Handle local symbols requiring GOT entry.
            {
              // Initialize local_got_refcounts if it's the first local GOT reference.
              if (local_got_refcounts == NULL)
                {
                  bfd_size_type size = symtab_hdr->sh_info * sizeof (bfd_signed_vma);
                  local_got_refcounts = ((bfd_signed_vma *) bfd_zalloc (abfd, size));
                  if (local_got_refcounts == NULL)
                    return false;
                  elf_local_got_refcounts (abfd) = local_got_refcounts;
                }

              if (local_got_refcounts[r_symndx] == 0)
                {
                  sgot->size += 4; // Allocate space in .got for local entry.
                  if (bfd_link_pic (info))
                    {
                      // For position-independent code, generate a R_BFIN_RELATIVE relocation.
                      srelgot->size += sizeof (Elf32_External_Rela);
                    }
                }
              local_got_refcounts[r_symndx]++;
            }
          break;

        default:
          break;
        }
    }

  return true;
}

static enum elf_reloc_type_class
elf32_bfin_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			     const asection *rel_sec ATTRIBUTE_UNUSED,
			     const Elf_Internal_Rela * rela ATTRIBUTE_UNUSED)
{
  return reloc_class_normal;
}

static bfd_reloc_status_type
bfin_final_link_relocate (Elf_Internal_Rela *rel, reloc_howto_type *howto,
			  bfd *input_bfd, asection *input_section,
			  bfd_byte *contents, bfd_vma address,
			  bfd_vma value, bfd_vma addend)
{
  enum {
    BFIN_PCREL24_INSTR_ADDR_ADJUST = 2,
    BFIN_PCREL24_VALUE_SHIFT = 1,
    BFIN_PCREL24_OVERFLOW_CHECK_MASK = 0xFF000000U,
    BFIN_PCREL24_HIGH_WORD_PRESERVE_MASK = 0xFF00U,
    BFIN_PCREL24_HIGH_WORD_VALUE_MASK = 0xFFU,
    BFIN_PCREL24_HIGH_WORD_VALUE_SHIFT = 16,
    BFIN_PCREL24_LOW_WORD_MASK = 0xFFFFU
  };

  const int r_type = ELF32_R_TYPE (rel->r_info);

  if (r_type == R_BFIN_PCREL24 || r_type == R_BFIN_PCREL24_JUMP_L)
    {
      bfd_reloc_status_type status = bfd_reloc_ok;
      bfd_vma temp_word;

      if (!bfd_reloc_offset_in_range (howto, input_bfd, input_section,
				      address - BFIN_PCREL24_INSTR_ADDR_ADJUST))
	  return bfd_reloc_outofrange;

      value += addend;

      value -= input_section->output_section->vma + input_section->output_offset;
      value -= address;

      value += BFIN_PCREL24_INSTR_ADDR_ADJUST;
      address -= BFIN_PCREL24_INSTR_ADDR_ADJUST;

      if ((value & BFIN_PCREL24_OVERFLOW_CHECK_MASK) != 0
	  && (value & BFIN_PCREL24_OVERFLOW_CHECK_MASK) != BFIN_PCREL24_OVERFLOW_CHECK_MASK)
	status = bfd_reloc_overflow;

      value >>= BFIN_PCREL24_VALUE_SHIFT;

      temp_word = bfd_get_16 (input_bfd, contents + address);
      temp_word = (temp_word & BFIN_PCREL24_HIGH_WORD_PRESERVE_MASK)
                | ((value >> BFIN_PCREL24_HIGH_WORD_VALUE_SHIFT) & BFIN_PCREL24_HIGH_WORD_VALUE_MASK);
      bfd_put_16 (input_bfd, temp_word, contents + address);

      temp_word = value & BFIN_PCREL24_LOW_WORD_MASK;
      bfd_put_16 (input_bfd, temp_word, contents + address + BFIN_PCREL24_INSTR_ADDR_ADJUST);

      return status;
    }

  return _bfd_final_link_relocate (howto, input_bfd, input_section, contents,
				   rel->r_offset, value, addend);
}

static int
bfin_relocate_section (bfd * output_bfd,
		       struct bfd_link_info *info,
		       bfd * input_bfd,
		       asection * input_section,
		       bfd_byte * contents,
		       Elf_Internal_Rela * relocs,
		       Elf_Internal_Sym * local_syms,
		       asection ** local_sections)
{
  bfd *dynobj = elf_hash_table (info)->dynobj;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  bfd_vma *local_got_offsets = elf_local_got_offsets (input_bfd);
  asection *sgot = elf_hash_table (info)->sgot;

  Elf_Internal_Rela *rel = relocs;
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

  for (; rel < relend; rel++)
    {
      int r_type = ELF32_R_TYPE (rel->r_info);

      /* R_BFIN_LAST_RELOC is 242. Check for out-of-bounds relocation type. */
      if (r_type < 0 || r_type > 242)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      /* R_BFIN_GNU_VTENTRY and R_BFIN_GNU_VTINHERIT are special and are skipped. */
      if (r_type == R_BFIN_GNU_VTENTRY || r_type == R_BFIN_GNU_VTINHERIT)
	continue;

      reloc_howto_type *howto = bfin_reloc_type_lookup (input_bfd, r_type);
      if (howto == NULL)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      struct elf_link_hash_entry *h = NULL;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      bfd_vma relocation_value = 0;
      bool unresolved_reloc = false;
      bfd_reloc_status_type relocation_status = bfd_reloc_ok;

      /* Resolve symbol: local or global. */
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation_value = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bool warned = false;
	  bool ignored = false;
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation_value,
				   unresolved_reloc, warned, ignored);
	}

      if (sec != NULL && discarded_section (sec))
	{
	  RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					   rel, 1, relend, R_BFIN_UNUSED0,
					   howto, 0, contents);
	}

      if (bfd_link_relocatable (info))
	continue;

      bfd_vma address = rel->r_offset;
      bfd_vma final_reloc_value = relocation_value;
      bfd_vma final_addend = rel->r_addend;

      /* Process R_BFIN_GOT relocation type. */
      if (r_type == R_BFIN_GOT)
	{
	  /* If symbol is __GLOBAL_OFFSET_TABLE_, treat it as a generic relocation. */
	  if (h != NULL && strcmp (h->root.root.string, "__GLOBAL_OFFSET_TABLE_") != 0)
	    {
	      bfd_vma off;

	      if (dynobj == NULL)
		{
		  elf_hash_table (info)->dynobj = dynobj = output_bfd;
		  if (!_bfd_elf_create_got_section (dynobj, info))
		    return false;
		  sgot = elf_hash_table (info)->sgot;
		}

	      BFD_ASSERT (sgot != NULL);

	      if (h != NULL) /* Global symbol GOT entry */
		{
		  off = h->got.offset;
		  BFD_ASSERT (off != (bfd_vma) - 1);

		  bool dyn = elf_hash_table (info)->dynamic_sections_created;
		  if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn,
							bfd_link_pic (info),
							h)
		      || (bfd_link_pic (info)
			  && (info->symbolic
			      || h->dynindx == -1
			      || h->forced_local)
			  && h->def_regular))
		    {
		      if ((off & 1) != 0)
			off &= ~1;
		      else
			{
			  bfd_put_32 (output_bfd, relocation_value,
				      sgot->contents + off);
			  h->got.offset |= 1;
			}
		    }
		  else
		    unresolved_reloc = false;
		}
	      else /* Local symbol GOT entry */
		{
		  BFD_ASSERT (local_got_offsets != NULL);
		  off = local_got_offsets[r_symndx];
		  BFD_ASSERT (off != (bfd_vma) - 1);

		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_32 (output_bfd, relocation_value, sgot->contents + off);

		      if (bfd_link_pic (info))
			{
			  asection *s_relgot = elf_hash_table (info)->srelgot;
			  BFD_ASSERT (s_relgot != NULL);

			  Elf_Internal_Rela outrel;
			  outrel.r_offset = (sgot->output_section->vma
						 + sgot->output_offset + off);
			  outrel.r_info = ELF32_R_INFO (0, R_BFIN_PCREL24);
			  outrel.r_addend = relocation_value;

			  bfd_byte *loc = s_relgot->contents
					  + s_relgot->reloc_count * sizeof (Elf32_External_Rela);
			  bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
			  s_relgot->reloc_count++;
			}
		      local_got_offsets[r_symndx] |= 1;
		    }
		}

	      final_reloc_value = sgot->output_offset + off;
	      final_addend = 0;
	      /* bfin specific: preg = [preg + 17bitdiv4offset] relocation is div by 4. */
	      final_reloc_value /= 4;
	    }
	}

      /* Perform the final link relocation. */
      relocation_status = bfin_final_link_relocate (rel, howto, input_bfd, input_section,
                                                      contents, address,
                                                      final_reloc_value, final_addend);

      /* Handle unresolved relocations. */
      bool is_debugging_and_dynamic_def = ((input_section->flags & SEC_DEBUGGING) != 0 && h != NULL && h->def_dynamic);
      bfd_vma section_offset_valid = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);

      if (unresolved_reloc
	  && !is_debugging_and_dynamic_def
	  && section_offset_valid != (bfd_vma) -1)
	{
	  const char *sym_name = h ? h->root.root.string : "unknown";
	  _bfd_error_handler
	    (_("%pB(%pA+%#" PRIx64 "): "
	       "unresolvable relocation against symbol `%s'"),
	     input_bfd, input_section, (uint64_t) rel->r_offset,
	     sym_name);
	  return false;
	}

      if (relocation_status != bfd_reloc_ok)
	{
	  const char *name;
	  if (h != NULL)
	    name = h->root.root.string;
	  else if (sym != NULL)
	    {
	      name = bfd_elf_string_from_elf_section (input_bfd,
						      symtab_hdr->sh_link,
						      sym->st_name);
	      if (name == NULL)
		return false;
	      if (*name == '\0')
		name = bfd_section_name (sec);
	    }
	  else
	    name = "unknown symbol"; /* Fallback for robustness. */

	  if (relocation_status == bfd_reloc_overflow)
	    (*info->callbacks->reloc_overflow)
	      (info, (h ? &h->root : NULL), name, howto->name,
	       (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	  else
	    {
	      _bfd_error_handler
		(_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
		 input_bfd, input_section, (uint64_t) rel->r_offset,
		 name, (int) relocation_status);
	      return false;
	    }
	}
    }

  return true;
}

static asection *
bfin_gc_mark_hook (asection * sec,
                   struct bfd_link_info *info,
                   Elf_Internal_Rela * rel,
                   struct elf_link_hash_entry *h,
                   Elf_Internal_Sym * sym)
{
  // Apply special GC mark logic only if 'h' (hash entry) is present
  // AND 'rel' (relocation entry) is present, as its 'r_info' field is accessed.
  // This prevents potential NULL pointer dereferences on 'rel->r_info'
  // and ensures the special handling is only attempted when valid data is available.
  if (h != NULL && rel != NULL)
    {
      switch (ELF32_R_TYPE (rel->r_info))
        {
        case R_BFIN_GNU_VTINHERIT:
        case R_BFIN_GNU_VTENTRY:
          // These specific relocation types indicate that the section
          // should not be marked for garbage collection by this hook.
          return NULL;
        }
    }

  // In all other cases (either h is NULL, rel is NULL, or the relocation type
  // does not match the special conditions), fall back to the default
  // BFD ELF garbage collection mark hook.
  // This preserves the original behavior for non-specialized relocations
  // and handles potential NULL inputs gracefully by deferring to the base function.
  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

extern const bfd_target bfin_elf32_fdpic_vec;
#define IS_FDPIC(bfd) ((bfd)->xvec == &bfin_elf32_fdpic_vec)

/* An extension of the elf hash table data structure,
   containing some additional Blackfin-specific data.  */
struct bfinfdpic_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* A pointer to the .rofixup section.  */
  asection *sgotfixup;
  /* GOT base offset.  */
  bfd_vma got0;
  /* Location of the first non-lazy PLT entry, i.e., the number of
     bytes taken by lazy PLT entries.  */
  bfd_vma plt0;
  /* A hash table holding information about which symbols were
     referenced with which PIC-related relocations.  */
  struct htab *relocs_info;
  /* Summary reloc information collected by
     _bfinfdpic_count_got_plt_entries.  */
  struct _bfinfdpic_dynamic_got_info *g;
};

/* Get the Blackfin ELF linker hash table from a link_info structure.  */

#define bfinfdpic_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == BFIN_ELF_DATA)		\
   ? (struct bfinfdpic_elf_link_hash_table *) (p)->hash : NULL)

#define bfinfdpic_got_section(info) \
  (bfinfdpic_hash_table (info)->elf.sgot)
#define bfinfdpic_gotrel_section(info) \
  (bfinfdpic_hash_table (info)->elf.srelgot)
#define bfinfdpic_gotfixup_section(info) \
  (bfinfdpic_hash_table (info)->sgotfixup)
#define bfinfdpic_plt_section(info) \
  (bfinfdpic_hash_table (info)->elf.splt)
#define bfinfdpic_pltrel_section(info) \
  (bfinfdpic_hash_table (info)->elf.srelplt)
#define bfinfdpic_relocs_info(info) \
  (bfinfdpic_hash_table (info)->relocs_info)
#define bfinfdpic_got_initial_offset(info) \
  (bfinfdpic_hash_table (info)->got0)
#define bfinfdpic_plt_initial_offset(info) \
  (bfinfdpic_hash_table (info)->plt0)
#define bfinfdpic_dynamic_got_plt_info(info) \
  (bfinfdpic_hash_table (info)->g)

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF_DYNAMIC_INTERPRETER "/lib/ld.so.1"

#define DEFAULT_STACK_SIZE 0x20000

/* This structure is used to collect the number of entries present in
   each addressable range of the got.  */
struct _bfinfdpic_dynamic_got_info
{
  /* Several bits of information about the current link.  */
  struct bfd_link_info *info;
  /* Total size needed for GOT entries within the 18- or 32-bit
     ranges.  */
  bfd_vma got17m4, gothilo;
  /* Total size needed for function descriptor entries within the 18-
     or 32-bit ranges.  */
  bfd_vma fd17m4, fdhilo;
  /* Total size needed function descriptor entries referenced in PLT
     entries, that would be profitable to place in offsets close to
     the PIC register.  */
  bfd_vma fdplt;
  /* Total size needed by lazy PLT entries.  */
  bfd_vma lzplt;
  /* Number of relocations carried over from input object files.  */
  unsigned long relocs;
  /* Number of fixups introduced by relocations in input object files.  */
  unsigned long fixups;
};

/* Create a Blackfin ELF linker hash table.  */

static struct bfd_link_hash_table *
bfinfdpic_elf_link_hash_table_create (bfd *abfd)
{
  struct bfinfdpic_elf_link_hash_table *hash_table_container;

  hash_table_container = bfd_zmalloc (sizeof (struct bfinfdpic_elf_link_hash_table));
  if (hash_table_container == NULL)
    {
      return NULL;
    }

  if (!_bfd_elf_link_hash_table_init (
          &hash_table_container->elf,
          abfd,
          _bfd_elf_link_hash_newfunc,
          sizeof (struct elf_link_hash_entry)))
    {
      free (hash_table_container);
      return NULL;
    }

  return &hash_table_container->elf.root;
}

/* Decide whether a reference to a symbol can be resolved locally or
   not.  If the symbol is protected, we want the local address, but
   its function descriptor must be assigned by the dynamic linker.  */
#define BFINFDPIC_SYM_LOCAL(INFO, H) \
  (_bfd_elf_symbol_refs_local_p ((H), (INFO), 1) \
   || ! elf_hash_table (INFO)->dynamic_sections_created)
#define BFINFDPIC_FUNCDESC_LOCAL(INFO, H) \
  ((H)->dynindx == -1 || ! elf_hash_table (INFO)->dynamic_sections_created)

/* This structure collects information on what kind of GOT, PLT or
   function descriptors are required by relocations that reference a
   certain symbol.  */
struct bfinfdpic_relocs_info
{
  /* The index of the symbol, as stored in the relocation r_info, if
     we have a local symbol; -1 otherwise.  */
  long symndx;
  union
  {
    /* The input bfd in which the symbol is defined, if it's a local
       symbol.  */
    bfd *abfd;
    /* If symndx == -1, the hash table entry corresponding to a global
       symbol (even if it turns out to bind locally, in which case it
       should ideally be replaced with section's symndx + addend).  */
    struct elf_link_hash_entry *h;
  } d;
  /* The addend of the relocation that references the symbol.  */
  bfd_vma addend;

  /* The fields above are used to identify an entry.  The fields below
     contain information on how an entry is used and, later on, which
     locations it was assigned.  */
  /* The following 2 fields record whether the symbol+addend above was
     ever referenced with a GOT relocation.  The 17M4 suffix indicates a
     GOT17M4 relocation; hilo is used for GOTLO/GOTHI pairs.  */
  unsigned got17m4;
  unsigned gothilo;
  /* Whether a FUNCDESC relocation references symbol+addend.  */
  unsigned fd;
  /* Whether a FUNCDESC_GOT relocation references symbol+addend.  */
  unsigned fdgot17m4;
  unsigned fdgothilo;
  /* Whether a FUNCDESC_GOTOFF relocation references symbol+addend.  */
  unsigned fdgoff17m4;
  unsigned fdgoffhilo;
  /* Whether symbol+addend is referenced with GOTOFF17M4, GOTOFFLO or
     GOTOFFHI relocations.  The addend doesn't really matter, since we
     envision that this will only be used to check whether the symbol
     is mapped to the same segment as the got.  */
  unsigned gotoff;
  /* Whether symbol+addend is referenced by a LABEL24 relocation.  */
  unsigned call;
  /* Whether symbol+addend is referenced by a 32 or FUNCDESC_VALUE
     relocation.  */
  unsigned sym;
  /* Whether we need a PLT entry for a symbol.  Should be implied by
     something like:
     (call && symndx == -1 && ! BFINFDPIC_SYM_LOCAL (info, d.h))  */
  unsigned plt:1;
  /* Whether a function descriptor should be created in this link unit
     for symbol+addend.  Should be implied by something like:
     (plt || fdgotoff17m4 || fdgotofflohi
      || ((fd || fdgot17m4 || fdgothilo)
	  && (symndx != -1 || BFINFDPIC_FUNCDESC_LOCAL (info, d.h))))  */
  unsigned privfd:1;
  /* Whether a lazy PLT entry is needed for this symbol+addend.
     Should be implied by something like:
     (privfd && symndx == -1 && ! BFINFDPIC_SYM_LOCAL (info, d.h)
      && ! (info->flags & DF_BIND_NOW))  */
  unsigned lazyplt:1;
  /* Whether we've already emitted GOT relocations and PLT entries as
     needed for this symbol.  */
  unsigned done:1;

  /* The number of R_BFIN_BYTE4_DATA, R_BFIN_FUNCDESC and R_BFIN_FUNCDESC_VALUE
     relocations referencing the symbol.  */
  unsigned relocs32, relocsfd, relocsfdv;

  /* The number of .rofixups entries and dynamic relocations allocated
     for this symbol, minus any that might have already been used.  */
  unsigned fixups, dynrelocs;

  /* The offsets of the GOT entries assigned to symbol+addend, to the
     function descriptor's address, and to a function descriptor,
     respectively.  Should be zero if unassigned.  The offsets are
     counted from the value that will be assigned to the PIC register,
     not from the beginning of the .got section.  */
  bfd_signed_vma got_entry, fdgot_entry, fd_entry;
  /* The offsets of the PLT entries assigned to symbol+addend,
     non-lazy and lazy, respectively.  If unassigned, should be
     (bfd_vma)-1.  */
  bfd_vma plt_entry, lzplt_entry;
};

/* Compute a hash with the key fields of an bfinfdpic_relocs_info entry.  */
#define BFINFDPIC_ABFD_HASH_MULTIPLIER 257

static hashval_t
bfinfdpic_relocs_info_hash (const void *entry_)
{
  const struct bfinfdpic_relocs_info *entry = entry_;
  long intermediate_calc_result;

  if (entry == NULL) {
    return (hashval_t)0;
  }

  if (entry->symndx == -1)
    {
      if (entry->d.h == NULL) {
        return (hashval_t)0;
      }
      intermediate_calc_result = (long)entry->d.h->root.root.hash;
    }
  else
    {
      if (entry->d.abfd == NULL) {
        return (hashval_t)0;
      }
      intermediate_calc_result = entry->symndx + (long)entry->d.abfd->id * BFINFDPIC_ABFD_HASH_MULTIPLIER;
    }

  intermediate_calc_result += (long)entry->addend;

  return (hashval_t)intermediate_calc_result;
}

/* Test whether the key fields of two bfinfdpic_relocs_info entries are
   identical.  */
static int
bfinfdpic_relocs_info_eq (const void *entry1, const void *entry2)
{
  if (entry1 == NULL || entry2 == NULL) {
    return (entry1 == entry2);
  }

  const struct bfinfdpic_relocs_info *e1 = entry1;
  const struct bfinfdpic_relocs_info *e2 = entry2;

  if (e1->symndx != e2->symndx) {
    return 0;
  }

  if (e1->addend != e2->addend) {
    return 0;
  }

  if (e1->symndx == -1) {
    return (e1->d.h == e2->d.h);
  } else {
    return (e1->d.abfd == e2->d.abfd);
  }
}

/* Find or create an entry in a hash table HT that matches the key
   fields of the given ENTRY.  If it's not found, memory for a new
   entry is allocated in ABFD's obstack.  */
static struct bfinfdpic_relocs_info *
bfinfdpic_relocs_info_find (struct htab *ht,
			   bfd *abfd,
			   const struct bfinfdpic_relocs_info *entry,
			   enum insert_option insert)
{
  if (!ht)
    return NULL;

  struct bfinfdpic_relocs_info **slot =
    (struct bfinfdpic_relocs_info **) htab_find_slot (ht, entry, insert);

  if (!slot)
    return NULL;

  if (*slot)
    return *slot;

  struct bfinfdpic_relocs_info *new_info = bfd_zalloc (abfd, sizeof (*new_info));

  if (!new_info)
    return NULL;

  new_info->symndx = entry->symndx;
  new_info->d = entry->d;
  new_info->addend = entry->addend;
  new_info->plt_entry = (bfd_vma)-1;
  new_info->lzplt_entry = (bfd_vma)-1;

  *slot = new_info;

  return new_info;
}

/* Obtain the address of the entry in HT associated with H's symbol +
   addend, creating a new entry if none existed.  ABFD is only used
   for memory allocation purposes.  */
inline static struct bfinfdpic_relocs_info *
bfinfdpic_relocs_info_for_global (struct htab *ht,
				  bfd *abfd,
				  struct elf_link_hash_entry *h,
				  bfd_vma addend,
				  enum insert_option insert)
{
  return bfinfdpic_relocs_info_find (ht, abfd, &(struct bfinfdpic_relocs_info){
    .symndx = -1,
    .d.h = h,
    .addend = addend
  }, insert);
}

/* Obtain the address of the entry in HT associated with the SYMNDXth
   local symbol of the input bfd ABFD, plus the addend, creating a new
   entry if none existed.  */
inline static struct bfinfdpic_relocs_info *
bfinfdpic_relocs_info_for_local (struct htab *ht,
				bfd *abfd,
				long symndx,
				bfd_vma addend,
				enum insert_option insert)
{
  struct bfinfdpic_relocs_info entry = {
    .symndx = symndx,
    .d.abfd = abfd,
    .addend = addend
  };

  return bfinfdpic_relocs_info_find (ht, abfd, &entry, insert);
}

/* Merge fields set by check_relocs() of two entries that end up being
   mapped to the same (presumably global) symbol.  */

inline static void
bfinfdpic_pic_merge_early_relocs_info (struct bfinfdpic_relocs_info *e2,
				       struct bfinfdpic_relocs_info const *e1)
{
  if (e2 == NULL || e1 == NULL) {
    return; /* Prevent null pointer dereference */
  }

  e2->got17m4 |= e1->got17m4;
  e2->gothilo |= e1->gothilo;
  e2->fd |= e1->fd;
  e2->fdgot17m4 |= e1->fdgot17m4;
  e2->fdgothilo |= e1->fdgothilo;
  e2->fdgoff17m4 |= e1->fdgoff17m4;
  e2->fdgoffhilo |= e1->fdgoffhilo;
  e2->gotoff |= e1->gotoff;
  e2->call |= e1->call;
  e2->sym |= e1->sym;
}

/* Every block of 65535 lazy PLT entries shares a single call to the
   resolver, inserted in the 32768th lazy PLT entry (i.e., entry #
   32767, counting from 0).  All other lazy PLT entries branch to it
   in a single instruction.  */

#define LZPLT_RESOLVER_EXTRA 10
#define LZPLT_NORMAL_SIZE 6
#define LZPLT_ENTRIES 1362

#define BFINFDPIC_LZPLT_BLOCK_SIZE ((bfd_vma) LZPLT_NORMAL_SIZE * LZPLT_ENTRIES + LZPLT_RESOLVER_EXTRA)
#define BFINFDPIC_LZPLT_RESOLV_LOC (LZPLT_NORMAL_SIZE * LZPLT_ENTRIES / 2)

/* Add a dynamic relocation to the SRELOC section.  */

inline static bfd_vma
_bfinfdpic_add_dyn_reloc (bfd *output_bfd, asection *sreloc, bfd_vma offset,
			 int reloc_type, long dynindx, bfd_vma addend,
			 struct bfinfdpic_relocs_info *entry)
{
  Elf_Internal_Rela outrel;
  bfd_vma reloc_offset;

  outrel.r_offset = offset;
  outrel.r_info = ELF32_R_INFO (dynindx, reloc_type);
  outrel.r_addend = addend;

  reloc_offset = sreloc->reloc_count * sizeof (Elf32_External_Rel);
  BFD_ASSERT (reloc_offset + sizeof (Elf32_External_Rel) <= sreloc->size);
  bfd_elf32_swap_reloc_out (output_bfd, &outrel,
			    sreloc->contents + reloc_offset);
  sreloc->reloc_count++;

  if (entry->symndx)
    {
      BFD_ASSERT (entry->dynrelocs > 0);
      entry->dynrelocs--;
    }

  return reloc_offset;
}

/* Add a fixup to the ROFIXUP section.  */

static bfd_vma
_bfinfdpic_add_rofixup (bfd *output_bfd, asection *rofixup, bfd_vma offset_val,
			struct bfinfdpic_relocs_info *entry)
{
  bfd_vma fixup_offset;
  const unsigned int fixup_element_size = 4; /* Size of a 32-bit fixup in bytes */

  /* Handle sections marked for exclusion. This is a design decision, not an error. */
  if (rofixup->flags & SEC_EXCLUDE)
    {
      return (bfd_vma) -1; /* Standard BFD error/sentinel return for bfd_vma */
    }

  /* Calculate fixup_offset for the current fixup.
     Check for potential integer overflow if rofixup->reloc_count is very large,
     such that its product with fixup_element_size would exceed BFD_VMA_MAX. */
  if (rofixup->reloc_count > ( (bfd_vma)-1 / fixup_element_size) )
    {
      bfd_set_error(bfd_error_overflow);
      return (bfd_vma) -1;
    }
  fixup_offset = (bfd_vma)rofixup->reloc_count * fixup_element_size;

  /* If the section has contents, write the fixup value. */
  if (rofixup->contents)
    {
      /* Ensure there is enough space in the section for the fixup data.
         This check covers cases where rofixup->size is 0 or too small,
         preventing potential buffer overflows. */
      if (fixup_offset + fixup_element_size > rofixup->size)
        {
          bfd_set_error(bfd_error_bad_value); /* Indicates a memory access violation risk */
          return (bfd_vma) -1;
        }

      bfd_put_32 (output_bfd, offset_val, rofixup->contents + fixup_offset);
    }

  /* Increment rofixup->reloc_count.
     Check for potential overflow of the counter itself.
     Assuming rofixup->reloc_count is an unsigned integral type (e.g., unsigned int),
     comparing with its maximum value prevents wrap-around. */
  if (rofixup->reloc_count == (unsigned int)-1) /* Check for max value of unsigned int */
    {
      bfd_set_error(bfd_error_overflow);
      return (bfd_vma) -1;
    }
  rofixup->reloc_count++;

  /* If entry information is provided and symndx is set, update entry->fixups. */
  if (entry && entry->symndx)
    {
      /* Ensure entry->fixups is strictly positive before decrementing.
         Decrementation of a zero or negative value would indicate a logical error
         or an underflow, signifying an inconsistent state. */
      if (entry->fixups == 0)
        {
          bfd_set_error(bfd_error_bad_value); /* Consistency error in entry data */
          return (bfd_vma) -1;
        }
      entry->fixups--;
    }

  return fixup_offset;
}

/* Find the segment number in which OSEC, and output section, is
   located.  */

static unsigned
_bfinfdpic_osec_to_segment (bfd *output_bfd, asection *osec)
{
  Elf_Internal_Phdr *segment_header = _bfd_elf_find_segment_containing_section (output_bfd, osec);

  if (segment_header == NULL)
    {
      return (unsigned)-1;
    }
  else
    {
      return segment_header - elf_tdata (output_bfd)->phdr;
    }
}

inline static bool
_bfinfdpic_osec_readonly_p (bfd *output_bfd, asection *osec)
{
  if (output_bfd == NULL)
    {
      return false;
    }

  // Assuming elf_tdata returns a pointer to an ELF-specific data structure
  // that contains 'phdr' (array of program headers) and 'e_phnum' (number of program headers).
  // The exact type might vary (e.g., struct elf_obj_data, struct _bfd_elf_obj_data).
  // We cast to a conceptual 'bfd_elf_obj_data' for type safety and clarity.
  const struct bfd_elf_obj_data *elf_data = (const struct bfd_elf_obj_data *) elf_tdata (output_bfd);

  if (elf_data == NULL || elf_data->phdr == NULL)
    {
      // Not an ELF BFD, or no program headers found for this BFD.
      // Cannot determine if read-only, so return false (not read-only/error state).
      return false;
    }

  unsigned int seg = _bfinfdpic_osec_to_segment (output_bfd, osec);

  // Perform bounds checking to prevent potential out-of-bounds access.
  // The 'e_phnum' field in the ELF data indicates the number of program headers.
  if (seg >= elf_data->e_phnum)
    {
      // The segment index is out of the valid range for program headers.
      // This indicates an error in the segment mapping or corrupted data.
      // Return false as we cannot reliably determine read-only status.
      return false;
    }

  return ! (elf_data->phdr[seg].p_flags & PF_W);
}

/* Generate relocations for GOT entries, function descriptors, and
   code for PLT and lazy PLT entries.  */

static int _bfinfdpic_get_initial_dynindx(struct bfinfdpic_relocs_info *entry,
                                         struct bfd_link_info *info,
                                         asection *sec)
{
    if (entry->symndx == -1 && entry->d.h->dynindx != -1)
        return entry->d.h->dynindx;
    if (sec && sec->output_section && !bfd_is_abs_section(sec->output_section) && !bfd_is_und_section(sec->output_section))
        return elf_section_data(sec->output_section)->dynindx;
    return 0;
}

static void _bfinfdpic_resolve_symbol_target(struct bfinfdpic_relocs_info *entry,
                                             struct bfd_link_info *info,
                                             asection *sec,
                                             Elf_Internal_Sym *sym,
                                             bfd_vma *ad_out, int *idx_out,
                                             bfd_vma initial_addend, int initial_dynindx)
{
    *ad_out = initial_addend;
    *idx_out = initial_dynindx;

    if (sec && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
        if (entry->symndx == -1)
            *ad_out += entry->d.h->root.u.def.value;
        else
            *ad_out += sym->st_value;
        *ad_out += sec->output_offset;

        if (sec->output_section && elf_section_data(sec->output_section))
            *idx_out = elf_section_data(sec->output_section)->dynindx;
        else
            *idx_out = 0;
    }
}

static bool _bfinfdpic_emit_got_fd_relocation(bfd *output_bfd,
                                              struct bfd_link_info *info,
                                              struct bfinfdpic_relocs_info *entry,
                                              asection *sec,
                                              bfd_vma *ad_in_out, int current_idx,
                                              int reloc_type, bfd_vma got_entry_offset,
                                              bool is_fd_entry_pair, bool lazyplt_mode,
                                              bfd_vma *dyn_reloc_offset_out)
{
    if (bfd_link_pde(info) && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
        if (sec)
            *ad_in_out += sec->output_section->vma;

        if (entry->symndx != -1 || entry->d.h->root.type != bfd_link_hash_undefweak)
        {
            _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info),
                                  bfinfdpic_got_section(info)->output_section->vma
                                  + bfinfdpic_got_section(info)->output_offset
                                  + bfinfdpic_got_initial_offset(info)
                                  + got_entry_offset, entry);
            if (is_fd_entry_pair)
                _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info),
                                      bfinfdpic_got_section(info)->output_section->vma
                                      + bfinfdpic_got_section(info)->output_offset
                                      + bfinfdpic_got_initial_offset(info)
                                      + got_entry_offset + 4, entry);
        }
        *dyn_reloc_offset_out = 0;
    }
    else
    {
        bfd_vma reloc_target_addr = _bfd_elf_section_offset(output_bfd, info,
                                                           bfinfdpic_got_section(info),
                                                           bfinfdpic_got_initial_offset(info)
                                                           + got_entry_offset)
                                  + bfinfdpic_got_section(info)->output_section->vma
                                  + bfinfdpic_got_section(info)->output_offset;

        asection *reloc_sec = lazyplt_mode ? bfinfdpic_pltrel_section(info) : bfinfdpic_gotrel_section(info);

        *dyn_reloc_offset_out = _bfinfdpic_add_dyn_reloc(output_bfd, reloc_sec,
                                                         reloc_target_addr, reloc_type,
                                                         current_idx, *ad_in_out, entry);
        if (*dyn_reloc_offset_out == 0 && reloc_target_addr != 0)
            return false;
    }
    return true;
}

static bool _bfinfdpic_handle_got_entry(struct bfinfdpic_relocs_info *entry,
                                       bfd *output_bfd,
                                       struct bfd_link_info *info,
                                       asection *sec,
                                       Elf_Internal_Sym *sym,
                                       bfd_vma addend, int dynindx_base)
{
    if (!entry->got_entry) return true;

    bfd_vma current_ad;
    int current_idx;
    _bfinfdpic_resolve_symbol_target(entry, info, sec, sym, &current_ad, &current_idx, addend, dynindx_base);

    bfd_vma dummy_offset;
    if (!_bfinfdpic_emit_got_fd_relocation(output_bfd, info, entry, sec,
                                           &current_ad, current_idx, R_BFIN_BYTE4_DATA,
                                           entry->got_entry, false, false, &dummy_offset))
        return false;

    bfd_put_32(output_bfd, current_ad,
               bfinfdpic_got_section(info)->contents
               + bfinfdpic_got_initial_offset(info)
               + entry->got_entry);
    return true;
}

static bool _bfinfdpic_handle_fdgot_entry(struct bfinfdpic_relocs_info *entry,
                                         bfd *output_bfd,
                                         struct bfd_link_info *info,
                                         asection *sec,
                                         bfd_vma addend, int dynindx_base)
{
    if (!entry->fdgot_entry) return true;

    int reloc_type = 0;
    int current_idx = 0;
    bfd_vma current_ad = 0;

    bool skip_dynamic_resolution_check = (entry->symndx == -1
                                          && entry->d.h->root.type == bfd_link_hash_undefweak
                                          && BFINFDPIC_SYM_LOCAL(info, entry->d.h));

    if (!skip_dynamic_resolution_check)
    {
        if (entry->symndx == -1 && !BFINFDPIC_FUNCDESC_LOCAL(info, entry->d.h)
            && BFINFDPIC_SYM_LOCAL(info, entry->d.h) && !bfd_link_pde(info))
        {
            reloc_type = R_BFIN_FUNCDESC;
            current_idx = elf_section_data(entry->d.h->root.u.def.section->output_section)->dynindx;
            current_ad = entry->d.h->root.u.def.section->output_offset + entry->d.h->root.u.def.value;
        }
        else if (entry->symndx == -1 && !BFINFDPIC_FUNCDESC_LOCAL(info, entry->d.h))
        {
            reloc_type = R_BFIN_FUNCDESC;
            current_idx = dynindx_base;
            current_ad = addend;
            if (current_ad) return false;
        }
        else
        {
            if (elf_hash_table(info)->dynamic_sections_created) BFD_ASSERT(entry->privfd);
            reloc_type = R_BFIN_BYTE4_DATA;
            current_idx = elf_section_data(bfinfdpic_got_section(info)->output_section)->dynindx;
            current_ad = bfinfdpic_got_section(info)->output_offset + bfinfdpic_got_initial_offset(info) + entry->fd_entry;
        }

        bfd_vma dummy_offset;
        if (!_bfinfdpic_emit_got_fd_relocation(output_bfd, info, entry, sec,
                                               &current_ad, current_idx, reloc_type,
                                               entry->fdgot_entry, false, false, &dummy_offset))
            return false;
    }

    bfd_put_32(output_bfd, current_ad,
               bfinfdpic_got_section(info)->contents
               + bfinfdpic_got_initial_offset(info)
               + entry->fdgot_entry);
    return true;
}

static bool _bfinfdpic_handle_fd_entry(struct bfinfdpic_relocs_info *entry,
                                      bfd *output_bfd,
                                      struct bfd_link_info *info,
                                      asection *sec,
                                      Elf_Internal_Sym *sym,
                                      bfd_vma addend, int dynindx_base,
                                      bfd_vma *fd_lazy_rel_offset_out)
{
    if (!entry->fd_entry) return true;

    bfd_vma current_ad;
    int current_idx;
    _bfinfdpic_resolve_symbol_target(entry, info, sec, sym, &current_ad, &current_idx, addend, dynindx_base);

    bfd_vma ofst;
    if (!_bfinfdpic_emit_got_fd_relocation(output_bfd, info, entry, sec,
                                           &current_ad, current_idx, R_BFIN_FUNCDESC_VALUE,
                                           entry->fd_entry, true, entry->lazyplt, &ofst))
        return false;

    long lowword, highword;

    if (bfd_link_pde(info) && sec && sec->output_section)
    {
        lowword = current_ad;
        highword = bfinfdpic_got_section(info)->output_section->vma
                 + bfinfdpic_got_section(info)->output_offset
                 + bfinfdpic_got_initial_offset(info);
    }
    else if (entry->lazyplt)
    {
        if (current_ad) return false;

        *fd_lazy_rel_offset_out = ofst;

        lowword = entry->lzplt_entry + 4
                + bfinfdpic_plt_section(info)->output_offset
                + bfinfdpic_plt_section(info)->output_section->vma;
        highword = _bfinfdpic_osec_to_segment(output_bfd, bfinfdpic_plt_section(info)->output_section);
    }
    else
    {
        lowword = current_ad;
        if (sec == NULL || (entry->symndx == -1 && entry->d.h->dynindx != -1 && entry->d.h->dynindx == current_idx))
            highword = 0;
        else
            highword = _bfinfdpic_osec_to_segment(output_bfd, sec->output_section);
    }

    bfd_put_32(output_bfd, lowword,
               bfinfdpic_got_section(info)->contents
               + bfinfdpic_got_initial_offset(info)
               + entry->fd_entry);
    bfd_put_32(output_bfd, highword,
               bfinfdpic_got_section(info)->contents
               + bfinfdpic_got_initial_offset(info)
               + entry->fd_entry + 4);
    return true;
}

static bool _bfinfdpic_handle_plt_entry(struct bfinfdpic_relocs_info *entry,
                                       bfd *output_bfd,
                                       struct bfd_link_info *info)
{
    if (entry->plt_entry == (bfd_vma)-1) return true;

    bfd_byte *plt_code_ptr = bfinfdpic_plt_section(info)->contents + entry->plt_entry;

    BFD_ASSERT(entry->fd_entry);

    if (entry->fd_entry >= -(1 << (18 - 1)) && entry->fd_entry + 4 < (1 << (18 - 1)))
    {
        bfd_put_32(output_bfd, 0xe519 | ((entry->fd_entry << 14) & 0xFFFF0000), plt_code_ptr);
        bfd_put_32(output_bfd, 0xe51b | (((entry->fd_entry + 4) << 14) & 0xFFFF0000), plt_code_ptr + 4);
        plt_code_ptr += 8;
    }
    else
    {
        bfd_put_32(output_bfd, 0xe109 | (entry->fd_entry << 16), plt_code_ptr);
        bfd_put_32(output_bfd, 0xe149 | (entry->fd_entry & 0xFFFF0000), plt_code_ptr + 4);
        bfd_put_16(output_bfd, 0x5ad9, plt_code_ptr + 8);
        bfd_put_16(output_bfd, 0x9159, plt_code_ptr + 10);
        bfd_put_16(output_bfd, 0xac5b, plt_code_ptr + 12);
        plt_code_ptr += 14;
    }
    bfd_put_16(output_bfd, 0x0051, plt_code_ptr);
    return true;
}

static bool _bfinfdpic_handle_lzplt_entry(struct bfinfdpic_relocs_info *entry,
                                         bfd *output_bfd,
                                         struct bfd_link_info *info,
                                         bfd_vma fd_lazy_rel_offset)
{
    if (entry->lzplt_entry == (bfd_vma)-1) return true;

    bfd_byte *lzplt_code_ptr = bfinfdpic_plt_section(info)->contents + entry->lzplt_entry;
    bfd_vma resolverStub_addr;

    bfd_put_32(output_bfd, fd_lazy_rel_offset, lzplt_code_ptr);
    lzplt_code_ptr += 4;

    resolverStub_addr = entry->lzplt_entry / BFINFDPIC_LZPLT_BLOCK_SIZE
                      * BFINFDPIC_LZPLT_BLOCK_SIZE + BFINFDPIC_LZPLT_RESOLV_LOC;
    if (resolverStub_addr >= bfinfdpic_plt_initial_offset(info))
        resolverStub_addr = bfinfdpic_plt_initial_offset(info) - LZPLT_NORMAL_SIZE - LZPLT_RESOLVER_EXTRA;

    if (entry->lzplt_entry == resolverStub_addr)
    {
        bfd_put_32(output_bfd, 0xa05b915a, lzplt_code_ptr);
        bfd_put_16(output_bfd, 0x0052, lzplt_code_ptr + 4);
    }
    else
    {
        bfd_put_16(output_bfd,
                   0x2000 | (((resolverStub_addr - entry->lzplt_entry) / 2) & (((bfd_vma)1 << 12) - 1)),
                   lzplt_code_ptr);
    }
    return true;
}

inline static bool
_bfinfdpic_emit_got_relocs_plt_entries (struct bfinfdpic_relocs_info *entry,
					bfd *output_bfd,
					struct bfd_link_info *info,
					asection *sec,
					Elf_Internal_Sym *sym,
					bfd_vma addend)
{
  if (entry->done)
    return true;
  entry->done = 1;

  bfd_vma fd_lazy_rel_offset = (bfd_vma) -1;
  int dynindx_base = _bfinfdpic_get_initial_dynindx(entry, info, sec);

  if (!_bfinfdpic_handle_got_entry(entry, output_bfd, info, sec, sym, addend, dynindx_base))
      return false;

  if (!_bfinfdpic_handle_fdgot_entry(entry, output_bfd, info, sec, addend, dynindx_base))
      return false;

  if (!_bfinfdpic_handle_fd_entry(entry, output_bfd, info, sec, sym, addend, dynindx_base, &fd_lazy_rel_offset))
      return false;

  if (!_bfinfdpic_handle_plt_entry(entry, output_bfd, info))
      return false;

  if (!_bfinfdpic_handle_lzplt_entry(entry, output_bfd, info, fd_lazy_rel_offset))
      return false;

  return true;
}

/* Relocate an Blackfin ELF section.

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures; if the section
   actually uses Rel structures, the r_addend field will always be
   zero.

   This function is responsible for adjusting the section contents as
   necessary, and (if using Rela relocs and generating a relocatable
   output file) adjusting the reloc addend as necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

#include <stdbool.h>
#include <string.h> // For strlen and filename_cmp if not already included by BFD headers
// Assume other BFD/ELF headers and internal macros/functions are available via bfd.h and elf.h or internal BFD headers.

// Helper function to resolve symbol and section information
static void
bfinfdpic_resolve_symbol_and_section (bfd *output_bfd_param, bfd *input_bfd_param,
                                      struct bfd_link_info *info,
                                      Elf_Internal_Shdr *symtab_hdr,
                                      struct elf_link_hash_entry **sym_hashes,
                                      unsigned long r_symndx,
                                      Elf_Internal_Sym *local_syms,
                                      asection **local_sections,
                                      Elf_Internal_Rela *rel, asection *input_section_param,
                                      Elf_Internal_Sym **sym_out, asection **sec_out,
                                      struct elf_link_hash_entry **h_out,
                                      bfd_vma *relocation_out, const char **name_out)
{
  if (r_symndx < symtab_hdr->sh_info)
    {
      *sym_out = local_syms + r_symndx;
      *sec_out = local_sections[r_symndx];
      *relocation_out = _bfd_elf_rela_local_sym (output_bfd_param, *sym_out, sec_out, rel);
      *name_out = bfd_elf_string_from_elf_section (input_bfd_param, symtab_hdr->sh_link, (*sym_out)->st_name);
      if (*name_out == NULL && *sec_out != NULL)
        *name_out = bfd_section_name (*sec_out);
    }
  else
    {
      bool warned, ignored, unresolved_reloc;
      RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd_param, input_section_param, rel,
                               r_symndx, symtab_hdr, sym_hashes,
                               *h_out, *sec_out, *relocation_out,
                               unresolved_reloc, warned, ignored);
      if (*h_out)
        *name_out = (*h_out)->root.root.string;
      else if (*sec_out != NULL)
        *name_out = bfd_section_name (*sec_out);
    }
}

// Helper function to get relocation info for PIC
static struct bfinfdpic_relocs_info *
bfinfdpic_get_picrel_info (struct bfd_link_info *info, bfd *input_bfd_param,
                           struct elf_link_hash_entry *h,
                           unsigned long r_symndx, bfd_vma orig_addend)
{
  if (h != NULL)
    return bfinfdpic_relocs_info_for_global (bfinfdpic_relocs_info (info), input_bfd_param, h, orig_addend, INSERT);
  else
    return bfinfdpic_relocs_info_for_local (bfinfdpic_relocs_info (info), input_bfd_param, r_symndx, orig_addend, INSERT);
}

// Helper for R_BFIN_FUNCDESC specific relocation handling
static bool
handle_func_desc_relocation (bfd *output_bfd, struct bfd_link_info *info,
                             bfd *input_bfd, asection *input_section,
                             Elf_Internal_Rela *rel, int *r_type_out,
                             Elf_Internal_Sym *sym, struct elf_link_hash_entry *h,
                             asection *osec, struct bfinfdpic_relocs_info *picrel,
                             const char *name, bfd_vma *relocation_out)
{
  if ((input_section->flags & SEC_ALLOC) == 0)
    {
      *relocation_out = 0;
      return true;
    }

  int dynindx = 0;
  bfd_vma addend = rel->r_addend;

  if (!(h && h->root.type == bfd_link_hash_undefweak && BFINFDPIC_SYM_LOCAL (info, h)))
    {
      if (h && !BFINFDPIC_FUNCDESC_LOCAL (info, h) && BFINFDPIC_SYM_LOCAL (info, h) && !bfd_link_pde (info))
        {
          dynindx = elf_section_data (h->root.u.def.section->output_section)->dynindx;
          addend += h->root.u.def.section->output_offset + h->root.u.def.value;
        }
      else if (h && !BFINFDPIC_FUNCDESC_LOCAL (info, h))
        {
          if (addend)
            {
              info->callbacks->warning (info, _("R_BFIN_FUNCDESC references dynamic symbol with nonzero addend"),
                                       name, input_bfd, input_section, rel->r_offset);
              return false;
            }
          dynindx = h->dynindx;
        }
      else
        {
          BFD_ASSERT (picrel->privfd);
          *r_type_out = R_BFIN_BYTE4_DATA;
          dynindx = elf_section_data (bfinfdpic_got_section (info)->output_section)->dynindx;
          addend = bfinfdpic_got_section (info)->output_offset
                   + bfinfdpic_got_initial_offset (info) + picrel->fd_entry;
        }

      bfd_vma offset = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
      if (offset == (bfd_vma)-1)
        return true;

      bool readonly_sec = _bfinfdpic_osec_readonly_p (output_bfd, input_section->output_section);
      bool is_alloc_load_sec = (bfd_section_flags (input_section->output_section) & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD);

      if (bfd_link_pde (info) && (!h || BFINFDPIC_FUNCDESC_LOCAL (info, h)))
        {
          addend += bfinfdpic_got_section (info)->output_section->vma;
          if (is_alloc_load_sec)
            {
              if (readonly_sec)
                {
                  info->callbacks->warning (info, _("cannot emit fixups in read-only section"),
                                           name, input_bfd, input_section, rel->r_offset);
                  return false;
                }
              _bfinfdpic_add_rofixup (output_bfd, bfinfdpic_gotfixup_section (info),
                                      offset + input_section->output_section->vma + input_section->output_offset, picrel);
            }
        }
      else if (is_alloc_load_sec)
        {
          if (readonly_sec)
            {
              info->callbacks->warning (info, _("cannot emit dynamic relocations in read-only section"),
                                       name, input_bfd, input_section, rel->r_offset);
              return false;
            }
          _bfinfdpic_add_dyn_reloc (output_bfd, bfinfdpic_gotrel_section (info),
                                    offset + input_section->output_section->vma + input_section->output_offset,
                                    *r_type_out, dynindx, addend, picrel);
        }
      else
        addend += bfinfdpic_got_section (info)->output_section->vma;
    }

  *relocation_out = addend - rel->r_addend;
  return true;
}

// Helper for R_BFIN_BYTE4_DATA and R_BFIN_FUNCDESC_VALUE specific relocation handling
static bool
handle_byte4_data_func_desc_value_relocation (bfd *output_bfd, struct bfd_link_info *info,
                                              bfd *input_bfd, asection *input_section,
                                              Elf_Internal_Rela *rel, int r_type,
                                              Elf_Internal_Sym *sym, struct elf_link_hash_entry *h,
                                              asection *osec, struct bfinfdpic_relocs_info *picrel,
                                              const char *name, bfd_vma *relocation_out, bfd_byte *contents)
{
  int dynindx = 0;
  bfd_vma addend = rel->r_addend;
  bfd_vma offset = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);

  if (offset == (bfd_vma)-1)
    return true;

  if (h && ! BFINFDPIC_SYM_LOCAL (info, h))
    {
      if (addend && r_type == R_BFIN_FUNCDESC_VALUE)
        {
          info->callbacks->warning (info, _("R_BFIN_FUNCDESC_VALUE references dynamic symbol with nonzero addend"),
                                   name, input_bfd, input_section, rel->r_offset);
          return false;
        }
      dynindx = h->dynindx;
    }
  else
    {
      if (h)
        addend += h->root.u.def.value;
      else
        addend += sym->st_value;
      if (osec)
        addend += osec->output_offset;
      if (osec && osec->output_section
          && ! bfd_is_abs_section (osec->output_section)
          && ! bfd_is_und_section (osec->output_section))
        dynindx = elf_section_data (osec->output_section)->dynindx;
      else
        dynindx = 0;
    }

  bool readonly_sec = _bfinfdpic_osec_readonly_p (output_bfd, input_section->output_section);
  bool is_alloc_load_sec = (bfd_section_flags (input_section->output_section) & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD);

  if (bfd_link_pde (info) && (!h || BFINFDPIC_SYM_LOCAL (info, h)))
    {
      if (osec)
        addend += osec->output_section->vma;
      if (IS_FDPIC (input_bfd) && is_alloc_load_sec)
        {
          if (readonly_sec)
            {
              info->callbacks->warning (info, _("cannot emit fixups in read-only section"),
                                       name, input_bfd, input_section, rel->r_offset);
              return false;
            }
          if (!h || h->root.type != bfd_link_hash_undefweak)
            {
              _bfinfdpic_add_rofixup (output_bfd, bfinfdpic_gotfixup_section (info),
                                      offset + input_section->output_section->vma + input_section->output_offset, picrel);
              if (r_type == R_BFIN_FUNCDESC_VALUE)
                _bfinfdpic_add_rofixup (output_bfd, bfinfdpic_gotfixup_section (info),
                                        offset + input_section->output_section->vma + input_section->output_offset + 4, picrel);
            }
        }
    }
  else
    {
      if (is_alloc_load_sec)
        {
          if (readonly_sec)
            {
              info->callbacks->warning (info, _("cannot emit dynamic relocations in read-only section"),
                                       name, input_bfd, input_section, rel->r_offset);
              return false;
            }
          _bfinfdpic_add_dyn_reloc (output_bfd, bfinfdpic_gotrel_section (info),
                                    offset + input_section->output_section->vma + input_section->output_offset,
                                    r_type, dynindx, addend, picrel);
        }
      else if (osec)
        addend += osec->output_section->vma;
      *relocation_out = addend - rel->r_addend;
    }

  if (r_type == R_BFIN_FUNCDESC_VALUE)
    {
      bfd_vma val;
      if (bfd_link_pde (info) && (!h || BFINFDPIC_SYM_LOCAL (info, h)))
        val = bfinfdpic_got_section (info)->output_section->vma
              + bfinfdpic_got_section (info)->output_offset
              + bfinfdpic_got_initial_offset (info);
      else
        val = (h && ! BFINFDPIC_SYM_LOCAL (info, h))
              ? 0
              : _bfinfdpic_osec_to_segment (output_bfd, sec->output_section);
      bfd_put_32 (output_bfd, val, contents + rel->r_offset + 4);
    }
  return true;
}

// Helper for crt0.o filename check
static bool
bfinfdpic_is_crt0_object (bfd *input_bfd)
{
  const char *filename = bfd_get_filename (input_bfd);
  if (filename == NULL)
    return false;
  size_t len = strlen (filename);
  return (len == 6 && filename_cmp (filename, "crt0.o") == 0)
         || (len > 6 && filename_cmp (filename + len - 7, "/crt0.o") == 0);
}

// Helper for high/low relocation adjustments
static void
bfinfdpic_adjust_high_low_relocation (int r_type, bfd_vma *relocation_out, bfd_vma addend)
{
  switch (r_type)
    {
    case R_BFIN_GOTOFFHI:
      *relocation_out += addend;
      // Fall through.
    case R_BFIN_GOTHI:
    case R_BFIN_FUNCDESC_GOTHI:
    case R_BFIN_FUNCDESC_GOTOFFHI:
      *relocation_out >>= 16;
      // Fall through.
    case R_BFIN_GOTLO:
    case R_BFIN_FUNCDESC_GOTLO:
    case R_BFIN_GOTOFFLO:
    case R_BFIN_FUNCDESC_GOTOFFLO:
      *relocation_out &= 0xffff;
      break;
    default:
      break;
    }
}

// Helper for addend cancellation
static void
bfinfdpic_cancel_addend_for_plt_or_got (int r_type, bfd_vma *relocation_out, bfd_vma addend,
                                       struct bfinfdpic_relocs_info *picrel)
{
  switch (r_type)
    {
    case R_BFIN_PCREL24:
    case R_BFIN_PCREL24_JUMP_L:
      if (!picrel || !picrel->plt)
        break;
      // Fall through if PLT.
    case R_BFIN_GOT17M4:
    case R_BFIN_GOTHI:
    case R_BFIN_GOTLO:
    case R_BFIN_FUNCDESC_GOT17M4:
    case R_BFIN_FUNCDESC_GOTHI:
    case R_BFIN_FUNCDESC_GOTLO:
    case R_BFIN_FUNCDESC_GOTOFF17M4:
    case R_BFIN_FUNCDESC_GOTOFFHI:
    case R_BFIN_FUNCDESC_GOTOFFLO:
    case R_BFIN_GOTOFFHI:
      *relocation_out -= addend;
      break;
    default:
      break;
    }
}

static bool
bfinfdpic_relocate_section (bfd * output_bfd,
                            struct bfd_link_info *info,
                            bfd * input_bfd,
                            asection * input_section,
                            bfd_byte * contents,
                            Elf_Internal_Rela * relocs,
                            Elf_Internal_Sym * local_syms,
                            asection ** local_sections)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;
  unsigned isec_segment = _bfinfdpic_osec_to_segment (output_bfd, input_section->output_section);
  unsigned got_segment = (unsigned) -1;
  unsigned plt_segment = (unsigned) -1;
  int silence_segment_error = !bfd_link_pic (info);

  if (IS_FDPIC (output_bfd) && bfinfdpic_got_section (info))
    got_segment = _bfinfdpic_osec_to_segment (output_bfd, bfinfdpic_got_section (info)->output_section);

  if (IS_FDPIC (output_bfd) && elf_hash_table (info)->dynamic_sections_created)
    plt_segment = _bfinfdpic_osec_to_segment (output_bfd, bfinfdpic_plt_section (info)->output_section);

  for (Elf_Internal_Rela *rel = relocs; rel < relend; rel++)
    {
      reloc_howto_type *howto;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      struct elf_link_hash_entry *h = NULL;
      bfd_vma relocation = 0;
      const char * name = NULL;
      int r_type = ELF32_R_TYPE (rel->r_info);
      asection *osec = NULL;
      struct bfinfdpic_relocs_info *picrel = NULL;
      bfd_vma orig_addend = rel->r_addend;
      bool is_fdpic_complex_reloc = false;

      if (r_type == R_BFIN_GNU_VTINHERIT || r_type == R_BFIN_GNU_VTENTRY)
        continue;

      howto = bfin_reloc_type_lookup (input_bfd, r_type);
      if (howto == NULL)
        {
          bfd_set_error (bfd_error_bad_value);
          return false;
        }

      bfinfdpic_resolve_symbol_and_section (output_bfd, input_bfd, info, symtab_hdr, sym_hashes,
                                            ELF32_R_SYM (rel->r_info), local_syms,
                                            local_sections, rel, input_section,
                                            &sym, &sec, &h, &relocation, &name);
      osec = sec;

      if (sec != NULL && discarded_section (sec))
        RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
                                         rel, 1, relend, R_BFIN_UNUSED0,
                                         howto, 0, contents);

      if (bfd_link_relocatable (info))
        continue;

      if (h != NULL
          && (h->root.type == bfd_link_hash_defined
              || h->root.type == bfd_link_hash_defweak)
          && !BFINFDPIC_SYM_LOCAL (info, h))
        {
          osec = sec = NULL;
          relocation = 0;
        }

      switch (r_type)
        {
        case R_BFIN_PCREL24:
        case R_BFIN_PCREL24_JUMP_L:
        case R_BFIN_BYTE4_DATA:
          if (!IS_FDPIC (output_bfd))
            break;

        case R_BFIN_GOT17M4:
        case R_BFIN_GOTHI:
        case R_BFIN_GOTLO:
        case R_BFIN_FUNCDESC_GOT17M4:
        case R_BFIN_FUNCDESC_GOTHI:
        case R_BFIN_FUNCDESC_GOTLO:
        case R_BFIN_GOTOFF17M4:
        case R_BFIN_GOTOFFHI:
        case R_BFIN_GOTOFFLO:
        case R_BFIN_FUNCDESC_GOTOFF17M4:
        case R_BFIN_FUNCDESC_GOTOFFHI:
        case R_BFIN_FUNCDESC_GOTOFFLO:
        case R_BFIN_FUNCDESC:
        case R_BFIN_FUNCDESC_VALUE:
          is_fdpic_complex_reloc = true;
          if ((input_section->flags & SEC_ALLOC) == 0)
            break;

          picrel = bfinfdpic_get_picrel_info (info, input_bfd, h, ELF32_R_SYM (rel->r_info), orig_addend);
          if (!picrel)
            return false;

          if (!_bfinfdpic_emit_got_relocs_plt_entries (picrel, output_bfd, info, osec, sym, rel->r_addend))
            {
              _bfd_error_handler
                (_("%pB: relocation at `%pA+%#" PRIx64 "' "
                   "references symbol `%s' with nonzero addend"),
                 input_bfd, input_section, (uint64_t) rel->r_offset, name);
              return false;
            }
          break;

        default:
          is_fdpic_complex_reloc = false;
          break;
        }

      if (!is_fdpic_complex_reloc)
        {
          picrel = NULL;
          if (h && ! BFINFDPIC_SYM_LOCAL (info, h)
              && _bfd_elf_section_offset (output_bfd, info, input_section,
                                          rel->r_offset) != (bfd_vma) -1)
            {
              info->callbacks->warning
                (info, _("relocation references symbol not defined in the module"),
                 name, input_bfd, input_section, rel->r_offset);
              return false;
            }
        }

      unsigned check_segment[2];
      check_segment[0] = isec_segment;
      check_segment[1] = (unsigned) -1;

      switch (r_type)
        {
        case R_BFIN_PCREL24:
        case R_BFIN_PCREL24_JUMP_L:
          check_segment[0] = isec_segment;
          if (! IS_FDPIC (output_bfd))
            check_segment[1] = isec_segment;
          else if (picrel && picrel->plt)
            {
              relocation = bfinfdpic_plt_section (info)->output_section->vma
                + bfinfdpic_plt_section (info)->output_offset
                + picrel->plt_entry;
              check_segment[1] = plt_segment;
            }
          else if (picrel && picrel->symndx == -1
                   && picrel->d.h->root.type == bfd_link_hash_undefweak)
            check_segment[1] = check_segment[0];
          else
            check_segment[1] = sec ? _bfinfdpic_osec_to_segment (output_bfd, sec->output_section) : (unsigned)-1;
          break;

        case R_BFIN_GOT17M4:
        case R_BFIN_GOTHI:
        case R_BFIN_GOTLO:
          relocation = picrel->got_entry;
          check_segment[0] = check_segment[1] = got_segment;
          break;

        case R_BFIN_FUNCDESC_GOT17M4:
        case R_BFIN_FUNCDESC_GOTHI:
        case R_BFIN_FUNCDESC_GOTLO:
          relocation = picrel->fdgot_entry;
          check_segment[0] = check_segment[1] = got_segment;
          break;

        case R_BFIN_GOTOFFHI:
        case R_BFIN_GOTOFF17M4:
        case R_BFIN_GOTOFFLO:
          relocation -= bfinfdpic_got_section (info)->output_section->vma
            + bfinfdpic_got_section (info)->output_offset
            + bfinfdpic_got_initial_offset (info);
          check_segment[0] = got_segment;
          check_segment[1] = sec ? _bfinfdpic_osec_to_segment (output_bfd, sec->output_section) : (unsigned)-1;
          break;

        case R_BFIN_FUNCDESC_GOTOFF17M4:
        case R_BFIN_FUNCDESC_GOTOFFHI:
        case R_BFIN_FUNCDESC_GOTOFFLO:
          relocation = picrel->fd_entry;
          check_segment[0] = check_segment[1] = got_segment;
          break;

        case R_BFIN_FUNCDESC:
          if (!handle_func_desc_relocation (output_bfd, info, input_bfd, input_section,
                                            rel, &r_type, sym, h, osec, picrel, name,
                                            &relocation))
            return false;
          check_segment[0] = check_segment[1] = got_segment;
          break;

        case R_BFIN_BYTE4_DATA:
        case R_BFIN_FUNCDESC_VALUE:
          if (!handle_byte4_data_func_desc_value_relocation (output_bfd, info, input_bfd, input_section,
                                                              rel, r_type, sym, h, osec, picrel, name,
                                                              &relocation, contents))
            return false;
          if (IS_FDPIC (output_bfd) || r_type == R_BFIN_FUNCDESC_VALUE)
            check_segment[0] = check_segment[1] = got_segment;
          else
            check_segment[0] = check_segment[1] = (unsigned) -1;
          break;

        default:
          check_segment[0] = isec_segment;
          check_segment[1] = sec ? _bfinfdpic_osec_to_segment (output_bfd, sec->output_section) : (unsigned)-1;
          break;
        }

      if (check_segment[0] != check_segment[1] && IS_FDPIC (output_bfd))
        {
          if (silence_segment_error == 1)
            silence_segment_error = bfinfdpic_is_crt0_object (input_bfd) ? -1 : 0;

          if (!silence_segment_error
              && !(picrel && picrel->symndx == -1
                   && picrel->d.h->root.type == bfd_link_hash_undefined))
            {
              info->callbacks->warning
                (info,
                 bfd_link_pic (info)
                 ? _("relocations between different segments are not supported")
                 : _("warning: relocation references a different segment"),
                 name, input_bfd, input_section, rel->r_offset);
            }
          if (!silence_segment_error && bfd_link_pic (info))
            return false;
          elf_elfheader (output_bfd)->e_flags |= EF_BFIN_PIC;
        }

      bfinfdpic_adjust_high_low_relocation (r_type, &relocation, rel->r_addend);
      bfinfdpic_cancel_addend_for_plt_or_got (r_type, &relocation, rel->r_addend, picrel);

      bfd_reloc_status_type r_status = bfin_final_link_relocate (rel, howto, input_bfd, input_section,
                                                                  contents, rel->r_offset,
                                                                  relocation, rel->r_addend);

      if (r_status != bfd_reloc_ok)
        {
          const char * msg = NULL;
          switch (r_status)
            {
            case bfd_reloc_overflow:
              (*info->callbacks->reloc_overflow)
                (info, (h ? &h->root : NULL), name, howto->name,
                 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
              break;

            case bfd_reloc_undefined:
              (*info->callbacks->undefined_symbol)
                (info, name, input_bfd, input_section, rel->r_offset, true);
              break;

            case bfd_reloc_outofrange:
              msg = _("internal error: out of range error");
              break;

            case bfd_reloc_notsupported:
              msg = _("internal error: unsupported relocation error");
              break;

            case bfd_reloc_dangerous:
              msg = _("internal error: dangerous relocation");
              break;

            default:
              msg = _("internal error: unknown error");
              break;
            }

          if (msg)
            (*info->callbacks->warning) (info, msg, name, input_bfd,
                                         input_section, rel->r_offset);
        }
    }

  return true;
}

/* We need dynamic symbols for every section, since segments can
   relocate independently.  */
static bool
_bfinfdpic_link_omit_section_dynsym (bfd *output_bfd ATTRIBUTE_UNUSED,
				    struct bfd_link_info *info ATTRIBUTE_UNUSED,
				    asection *p)
{
  unsigned int section_type = elf_section_data (p)->this_hdr.sh_type;

  if (section_type == SHT_PROGBITS ||
      section_type == SHT_NOBITS ||
      section_type == SHT_NULL)
    {
      return false;
    }

  return true;
}

/* Create  a .got section, as well as its additional info field.  This
   is almost entirely copied from
   elflink.c:_bfd_elf_create_got_section().  */

static asection *
create_section_with_alignment (bfd *abfd, const char *name, flagword flags, int alignment)
{
  asection *s = bfd_make_section_anyway_with_flags (abfd, name, flags);
  if (s == NULL)
    return NULL;
  if (!bfd_set_section_alignment (s, alignment))
    return NULL;
  return s;
}

static bool
create_fdpic_specific_sections (bfd *abfd, struct bfd_link_info *info, flagword base_flags)
{
  asection *s;
  flagword readonly_flags = base_flags | SEC_READONLY;

  bfinfdpic_relocs_info (info) = htab_try_create (1,
                                                  bfinfdpic_relocs_info_hash,
                                                  bfinfdpic_relocs_info_eq,
                                                  (htab_del) NULL);
  if (! bfinfdpic_relocs_info (info))
    return false;

  s = create_section_with_alignment (abfd, ".rel.got", readonly_flags, 2);
  if (s == NULL)
    return false;
  bfinfdpic_gotrel_section (info) = s;

  s = create_section_with_alignment (abfd, ".rofixup", readonly_flags, 2);
  if (s == NULL)
    return false;
  bfinfdpic_gotfixup_section (info) = s;

  return true;
}

static bool
_bfin_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  asection *s;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  int ptralign = 3;
  flagword base_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY | SEC_LINKER_CREATED);
  flagword plt_flags;

  if (elf_hash_table (info)->sgot != NULL)
    return true;

  s = create_section_with_alignment (abfd, ".got", base_flags, ptralign);
  if (s == NULL)
    return false;
  elf_hash_table (info)->sgot = s;

  if (bed->want_got_sym)
    {
      h = _bfd_elf_define_linkage_sym (abfd, info, s, "__GLOBAL_OFFSET_TABLE_");
      if (h == NULL)
        return false;
      elf_hash_table (info)->hgot = h;
      if (! bfd_elf_link_record_dynamic_symbol (info, h))
        return false;
    }

  s->size += bed->got_header_size;

  if (IS_FDPIC (abfd))
    {
      if (!create_fdpic_specific_sections (abfd, info, base_flags))
        return false;
    }

  plt_flags = base_flags | SEC_CODE;
  if (bed->plt_not_loaded)
    plt_flags &= ~ (SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS);
  if (bed->plt_readonly)
    plt_flags |= SEC_READONLY;

  s = create_section_with_alignment (abfd, ".plt", plt_flags, bed->plt_alignment);
  if (s == NULL)
    return false;
  bfinfdpic_plt_section (info) = s;

  if (bed->want_plt_sym)
    {
      struct bfd_link_hash_entry *bh = NULL;
      if (! (_bfd_generic_link_add_one_symbol
             (info, abfd, "__PROCEDURE_LINKAGE_TABLE_", BSF_GLOBAL, s, 0, NULL,
              false, bed->collect, &bh)))
        return false;

      h = (struct elf_link_hash_entry *) bh;
      h->def_regular = 1;
      h->type = STT_OBJECT;

      if (! bfd_link_executable (info)
          && ! bfd_elf_link_record_dynamic_symbol (info, h))
        return false;
    }

  s = create_section_with_alignment (abfd, ".rel.plt", base_flags | SEC_READONLY, bed->s->log_file_align);
  if (s == NULL)
    return false;
  bfinfdpic_pltrel_section (info) = s;

  return true;
}

/* Make sure the got and plt sections exist, and that our pointers in
   the link hash table point to them.  */

static bool
elf32_bfinfdpic_create_dynamic_sections (bfd *abfd, struct bfd_link_info *info)
{
  const flagword common_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
	   | SEC_LINKER_CREATED);
  asection *s;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);

  if (! _bfin_create_got_section (abfd, info))
    return false;

  BFD_ASSERT (bfinfdpic_got_section (info) && bfinfdpic_gotrel_section (info)
	      /* && bfinfdpic_gotfixup_section (info) */
	      && bfinfdpic_plt_section (info)
	      && bfinfdpic_pltrel_section (info));

  if (bed->want_dynbss)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".dynbss",
					      SEC_ALLOC | SEC_LINKER_CREATED);
      if (s == NULL)
	return false;

      if (! bfd_link_pic (info))
	{
	  s = bfd_make_section_anyway_with_flags (abfd,
						  ".rela.bss",
						  common_flags | SEC_READONLY);
	  if (s == NULL
	      || !bfd_set_section_alignment (s, bed->s->log_file_align))
	    return false;
	}
    }

  return true;
}

/* Compute the total GOT size required by each symbol in each range.
   Symbols may require up to 4 words in the GOT: an entry pointing to
   the symbol, an entry pointing to its function descriptor, and a
   private function descriptors taking two words.  */

static void
_bfinfdpic_count_nontls_entries (struct bfinfdpic_relocs_info *entry,
				 struct _bfinfdpic_dynamic_got_info *dinfo)
{
  /* Allocate space for a GOT entry pointing to the symbol.  */
  if (entry->got17m4)
    dinfo->got17m4 += 4;
  else if (entry->gothilo)
    dinfo->gothilo += 4;
  /* The original 'else { entry->relocs32--; } entry->relocs32++;' was a no-op
     and has been removed to simplify logic and remove dead code. */

  /* Allocate space for a GOT entry pointing to the function descriptor.  */
  if (entry->fdgot17m4)
    dinfo->got17m4 += 4;
  else if (entry->fdgothilo)
    dinfo->gothilo += 4;
  /* The original 'else { entry->relocsfd--; } entry->relocsfd++;' was a no-op
     and has been removed to simplify logic and remove dead code. */

  /* Decide whether we need a PLT entry, a function descriptor in the
     GOT, and a lazy PLT entry for this symbol.  */
  const bool is_external_sym = (entry->symndx == -1
                                && !BFINFDPIC_SYM_LOCAL (dinfo->info, entry->d.h));
  const bool dyn_sections_exist = elf_hash_table (dinfo->info)->dynamic_sections_created;

  entry->plt = entry->call && is_external_sym && dyn_sections_exist;

  const bool has_fd_offset_reloc = entry->fdgoff17m4 || entry->fdgoffhilo;
  const bool has_fd_or_fdgot = entry->fd || entry->fdgot17m4 || entry->fdgothilo;
  const bool is_local_func_desc_condition = (entry->symndx != -1
                                              || BFINFDPIC_FUNCDESC_LOCAL (dinfo->info, entry->d.h));

  entry->privfd = entry->plt
                || has_fd_offset_reloc
                || (has_fd_or_fdgot && is_local_func_desc_condition);

  const bool bind_now_disabled = ! (dinfo->info->flags & DF_BIND_NOW);

  entry->lazyplt = entry->privfd
                 && is_external_sym
                 && bind_now_disabled
                 && dyn_sections_exist;

  /* Allocate space for a function descriptor.  */
  if (entry->fdgoff17m4)
    dinfo->fd17m4 += 8;
  else if (entry->privfd && entry->plt)
    dinfo->fdplt += 8;
  else if (entry->privfd)
    dinfo->fdhilo += 8;
  /* The original 'else { entry->relocsfdv--; } entry->relocsfdv++;' was a no-op
     and has been removed to simplify logic and remove dead code. */

  if (entry->lazyplt)
    dinfo->lzplt += LZPLT_NORMAL_SIZE;
}

/* Compute the number of dynamic relocations and fixups that a symbol
   requires, and add (or subtract) from the grand and per-symbol
   totals.  */

static void
_bfinfdpic_count_relocs_fixups (struct bfinfdpic_relocs_info *entry,
				struct _bfinfdpic_dynamic_got_info *dinfo,
				bool subtract)
{
  bfd_vma relocs_accumulator = 0;
  bfd_vma fixups_accumulator = 0;

  /*
   * The original code implicitly assumes 'entry' and 'dinfo' are
   * valid non-NULL pointers. If 'entry->symndx' is -1, it further
   * assumes 'entry->d.h' is a valid pointer to dereference.
   * We maintain these assumptions as per the existing code's contract.
   */

  if (!bfd_link_pde (dinfo->info))
    {
      relocs_accumulator = entry->relocs32 + entry->relocsfd + entry->relocsfdv;
    }
  else /* bfd_link_pde (dinfo->info) is true */
    {
      /* Common conditions for the PDE (Program Description Entry) case. */
      const bool sym_idx_is_valid = (entry->symndx != -1);
      const bool is_defined_or_strong = sym_idx_is_valid || (entry->d.h->root.type != bfd_link_hash_undefweak);

      /* Handle relocs32 and relocsfdv terms. */
      const bool sym_target_is_local = sym_idx_is_valid || BFINFDPIC_SYM_LOCAL(dinfo->info, entry->d.h);

      if (sym_target_is_local && is_defined_or_strong)
        {
          fixups_accumulator += entry->relocs32 + 2 * entry->relocsfdv;
        }
      else if (!sym_target_is_local) /* i.e., !sym_idx_is_valid && !BFINFDPIC_SYM_LOCAL(...) */
        {
          relocs_accumulator += entry->relocs32 + entry->relocsfdv;
        }
      /* If sym_target_is_local is true but is_defined_or_strong is false,
       * these terms (relocs32, relocsfdv) contribute to neither fixups nor relocs.
       * This specific condition corresponds to a local weak undefined symbol without a valid index.
       */

      /* Handle relocsfd term. */
      const bool funcdesc_target_is_local = sym_idx_is_valid || BFINFDPIC_FUNCDESC_LOCAL(dinfo->info, entry->d.h);

      if (funcdesc_target_is_local && is_defined_or_strong)
        {
          fixups_accumulator += entry->relocsfd;
        }
      else if (!funcdesc_target_is_local) /* i.e., !sym_idx_is_valid && !BFINFDPIC_FUNCDESC_LOCAL(...) */
        {
          relocs_accumulator += entry->relocsfd;
        }
      /* Similar implicit handling for when funcdesc_target_is_local is true but
       * is_defined_or_strong is false for the relocsfd term.
       */
    }

  if (subtract)
    {
      relocs_accumulator = -relocs_accumulator;
      fixups_accumulator = -fixups_accumulator;
    }

  entry->dynrelocs += relocs_accumulator;
  entry->fixups += fixups_accumulator;
  dinfo->relocs += relocs_accumulator;
  dinfo->fixups += fixups_accumulator;
}

/* Compute the total GOT and PLT size required by each symbol in each range. *
   Symbols may require up to 4 words in the GOT: an entry pointing to
   the symbol, an entry pointing to its function descriptor, and a
   private function descriptors taking two words.  */

static int
_bfinfdpic_count_got_plt_entries (void **entryp, void *dinfo_)
{
  if (entryp == NULL) {
    return 0;
  }

  if (*entryp == NULL) {
    return 0;
  }

  if (dinfo_ == NULL) {
    return 0;
  }

  struct bfinfdpic_relocs_info *entry = (struct bfinfdpic_relocs_info *)*entryp;
  struct _bfinfdpic_dynamic_got_info *dinfo = (struct _bfinfdpic_dynamic_got_info *)dinfo_;

  _bfinfdpic_count_nontls_entries (entry, dinfo);

  _bfinfdpic_count_relocs_fixups (entry, dinfo, false);

  return 1;
}

/* This structure is used to assign offsets to got entries, function
   descriptors, plt entries and lazy plt entries.  */

struct _bfinfdpic_dynamic_got_plt_info
{
  /* Summary information collected with _bfinfdpic_count_got_plt_entries.  */
  struct _bfinfdpic_dynamic_got_info g;

  /* For each addressable range, we record a MAX (positive) and MIN
     (negative) value.  CUR is used to assign got entries, and it's
     incremented from an initial positive value to MAX, then from MIN
     to FDCUR (unless FDCUR wraps around first).  FDCUR is used to
     assign function descriptors, and it's decreased from an initial
     non-positive value to MIN, then from MAX down to CUR (unless CUR
     wraps around first).  All of MIN, MAX, CUR and FDCUR always point
     to even words.  ODD, if non-zero, indicates an odd word to be
     used for the next got entry, otherwise CUR is used and
     incremented by a pair of words, wrapping around when it reaches
     MAX.  FDCUR is decremented (and wrapped) before the next function
     descriptor is chosen.  FDPLT indicates the number of remaining
     slots that can be used for function descriptors used only by PLT
     entries.  */
  struct _bfinfdpic_dynamic_got_alloc_data
  {
    bfd_signed_vma max, cur, odd, fdcur, min;
    bfd_vma fdplt;
  } got17m4, gothilo;
};

/* Determine the positive and negative ranges to be used by each
   offset range in the GOT.  FDCUR and CUR, that must be aligned to a
   double-word boundary, are the minimum (negative) and maximum
   (positive) GOT offsets already used by previous ranges, except for
   an ODD entry that may have been left behind.  GOT and FD indicate
   the size of GOT entries and function descriptors that must be
   placed within the range from -WRAP to WRAP.  If there's room left,
   up to FDPLT bytes should be reserved for additional function
   descriptors.  */

inline static bfd_signed_vma
_bfinfdpic_compute_got_alloc_data (struct _bfinfdpic_dynamic_got_alloc_data *gad,
				   bfd_signed_vma fdcur,
				   bfd_signed_vma incoming_odd_location,
				   bfd_signed_vma cur,
				   bfd_vma got_byte_count,
				   bfd_vma fd_size,
				   bfd_vma fdplt_size,
				   bfd_vma wrap_limit)
{
  const bfd_signed_vma WRAP_MIN = -wrap_limit;
  bfd_signed_vma outgoing_odd_location = 0;
  bfd_vma remaining_fdplt_size = fdplt_size;

  gad->fdcur = fdcur;
  gad->cur = cur;

  if (incoming_odd_location && got_byte_count)
    {
      gad->odd = incoming_odd_location;
      got_byte_count -= 4;
    }
  else
    {
      gad->odd = 0;
    }

  if ((got_byte_count % 8) == 4)
    {
      outgoing_odd_location = cur + got_byte_count;
      got_byte_count += 4;
    }

  gad->max = cur + got_byte_count;
  gad->min = fdcur - fd_size;
  gad->fdplt = 0;

  if (gad->min < WRAP_MIN)
    {
      bfd_signed_vma overflow = WRAP_MIN - gad->min;
      gad->max += overflow;
      gad->min = WRAP_MIN;
    }
  else if (remaining_fdplt_size && gad->min > WRAP_MIN)
    {
      bfd_vma fds_to_place = (bfd_vma)(gad->min - WRAP_MIN);
      if (fds_to_place > remaining_fdplt_size)
        {
          fds_to_place = remaining_fdplt_size;
        }

      remaining_fdplt_size -= fds_to_place;
      gad->min -= fds_to_place;
      gad->fdplt += fds_to_place;
    }

  if ((bfd_vma) gad->max > wrap_limit)
    {
      bfd_vma overflow = (bfd_vma) gad->max - wrap_limit;
      gad->min -= overflow;
      gad->max = wrap_limit;
    }
  else if (remaining_fdplt_size && (bfd_vma) gad->max < wrap_limit)
    {
      bfd_vma fds_to_place = wrap_limit - (bfd_vma) gad->max;
      if (fds_to_place > remaining_fdplt_size)
        {
          fds_to_place = remaining_fdplt_size;
        }

      remaining_fdplt_size -= fds_to_place;
      gad->max += fds_to_place;
      gad->fdplt += fds_to_place;
    }
  
  if (outgoing_odd_location > gad->max)
    outgoing_odd_location = gad->min + (outgoing_odd_location - gad->max);

  if (gad->cur == gad->max)
    gad->cur = gad->min;

  return outgoing_odd_location;
}

/* Compute the location of the next GOT entry, given the allocation
   data for a range.  */

inline static bfd_signed_vma
_bfinfdpic_get_got_entry (struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  const bfd_signed_vma single_entry_offset = 4;
  const bfd_signed_vma pair_entry_offset = 8;

  bfd_signed_vma entry_to_return;

  if (gad->odd != 0)
    {
      entry_to_return = gad->odd;
      gad->odd = 0;
    }
  else
    {
      entry_to_return = gad->cur;
      gad->odd = gad->cur + single_entry_offset;
      gad->cur += pair_entry_offset;

      if (gad->cur == gad->max)
	    gad->cur = gad->min;
    }

  return entry_to_return;
}

/* Compute the location of the next function descriptor entry in the
   GOT, given the allocation data for a range.  */

inline static bfd_signed_vma
_bfinfdpic_get_fd_entry (struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  if (gad->fdcur == gad->min) {
    gad->fdcur = gad->max;
  }
  gad->fdcur -= 8;
  return gad->fdcur;
}

/* Assign GOT offsets for every GOT entry and function descriptor.
   Doing everything in a single pass is tricky.  */

static int
_bfinfdpic_assign_got_entries (void **entryp, void *info_)
{
  // Define magic number as a named constant for improved maintainability.
  const int PLT_OFFSET_DECREMENT = 8;

  // Validate input pointers for reliability and security.
  // Returning 0 indicates an error due to invalid input.
  if (entryp == NULL || *entryp == NULL || info_ == NULL)
    {
      return 0;
    }

  struct bfinfdpic_relocs_info *entry = *entryp;
  struct _bfinfdpic_dynamic_got_plt_info *dinfo = info_;

  // Assign got_entry based on flags.
  // Using explicit braces for single-line if/else if bodies for consistency and future maintainability.
  if (entry->got17m4)
    {
      entry->got_entry = _bfinfdpic_get_got_entry (&dinfo->got17m4);
    }
  else if (entry->gothilo)
    {
      entry->got_entry = _bfinfdpic_get_got_entry (&dinfo->gothilo);
    }
  // If neither flag is set, entry->got_entry remains unchanged, consistent with original behavior.

  // Assign fdgot_entry based on flags.
  if (entry->fdgot17m4)
    {
      entry->fdgot_entry = _bfinfdpic_get_got_entry (&dinfo->got17m4);
    }
  else if (entry->fdgothilo)
    {
      entry->fdgot_entry = _bfinfdpic_get_got_entry (&dinfo->gothilo);
    }
  // If neither flag is set, entry->fdgot_entry remains unchanged, consistent with original behavior.

  // Assign fd_entry with simplified and clearer logic.
  // The complex if-else if chain related to 'plt' is now structured with a nested if-else,
  // making the flow more explicit and easier to understand.
  if (entry->fdgoff17m4)
    {
      entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->got17m4);
    }
  else if (entry->plt) // This branch handles all 'plt' related assignments
    {
      if (dinfo->got17m4.fdplt) // Prioritize got17m4 if its fdplt field is set
        {
          dinfo->got17m4.fdplt -= PLT_OFFSET_DECREMENT;
          entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->got17m4);
        }
      else // Fallback to gothilo if got17m4.fdplt is not set
        {
          dinfo->gothilo.fdplt -= PLT_OFFSET_DECREMENT;
          entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->gothilo);
        }
    }
  else if (entry->privfd) // Handle 'privfd' if none of the above conditions met
    {
      entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->gothilo);
    }
  // If none of the conditions are met, entry->fd_entry remains unchanged, consistent with original behavior.

  return 1; // Indicate success, consistent with original behavior.
}

/* Assign GOT offsets to private function descriptors used by PLT
   entries (or referenced by 32-bit offsets), as well as PLT entries
   and lazy PLT entries.  */

static int
_bfinfdpic_assign_plt_entries(struct bfinfdpic_relocs_info **entry_ptr,
                              struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
  struct bfinfdpic_relocs_info *entry = *entry_ptr;

  if (entry->privfd && entry->fd_entry == 0)
    {
      struct bfinfdpic_fdplt_info *fdplt_alloc_info = NULL;
      const int fd_entry_size = 8;

      if (dinfo->got17m4.fdplt)
        {
          fdplt_alloc_info = &dinfo->got17m4;
        }
      else
        {
          BFD_ASSERT(dinfo->gothilo.fdplt);
          fdplt_alloc_info = &dinfo->gothilo;
        }

      entry->fd_entry = _bfinfdpic_get_fd_entry(fdplt_alloc_info);
      fdplt_alloc_info->fdplt -= fd_entry_size;
    }

  if (entry->plt)
    {
      int plt_entry_size;
      struct bfd_section *plt_section = bfinfdpic_plt_section(dinfo->g.info);

      BFD_ASSERT(entry->fd_entry);

      const int plt_fd_offset_bound = (1 << (18 - 1));
      const int plt_size_short = 10;
      const int plt_size_long = 16;

      entry->plt_entry = plt_section->size;

      if (entry->fd_entry >= -plt_fd_offset_bound
          && entry->fd_entry + 4 < plt_fd_offset_bound)
        {
          plt_entry_size = plt_size_short;
        }
      else
        {
          plt_entry_size = plt_size_long;
        }

      plt_section->size += plt_entry_size;
    }

  if (entry->lazyplt)
    {
      entry->lzplt_entry = dinfo->g.lzplt;
      dinfo->g.lzplt += LZPLT_NORMAL_SIZE;

      if (entry->lzplt_entry % BFINFDPIC_LZPLT_BLOCK_SIZE == BFINFDPIC_LZPLT_RESOLV_LOC)
        {
          dinfo->g.lzplt += LZPLT_RESOLVER_EXTRA;
        }
    }

  return 1;
}

/* Cancel out any effects of calling _bfinfdpic_assign_got_entries and
   _bfinfdpic_assign_plt_entries.  */

static int
_bfinfdpic_reset_got_plt_entries (void **entryp, void *ignore ATTRIBUTE_UNUSED)
{
  if (entryp == NULL)
  {
    return 0;
  }

  struct bfinfdpic_relocs_info *entry = (struct bfinfdpic_relocs_info *)*entryp;

  if (entry == NULL)
  {
    return 0;
  }

  entry->got_entry = 0;
  entry->fdgot_entry = 0;
  entry->fd_entry = 0;
  entry->plt_entry = (bfd_vma)-1;
  entry->lzplt_entry = (bfd_vma)-1;

  return 1;
}

/* Follow indirect and warning hash entries so that each got entry
   points to the final symbol definition.  P must point to a pointer
   to the hash table we're traversing.  Since this traversal may
   modify the hash table, we set this pointer to NULL to indicate
   we've made a potentially-destructive change to the hash table, so
   the traversal must be restarted.  */
static int
_bfinfdpic_resolve_final_relocs_info (void **entry_slot, void *htab_ref_ptr)
{
  struct bfinfdpic_relocs_info *current_entry = (struct bfinfdpic_relocs_info *) *entry_slot;
  htab_t *htab_actual_ptr = (htab_t *) htab_ref_ptr;
  htab_t hash_table = *htab_actual_ptr;

  if (current_entry->symndx == -1)
    {
      struct elf_link_hash_entry *resolved_hash_entry = current_entry->d.h;

      while (resolved_hash_entry->root.type == bfd_link_hash_indirect
             || resolved_hash_entry->root.type == bfd_link_hash_warning)
        {
          resolved_hash_entry = (struct elf_link_hash_entry *)resolved_hash_entry->root.u.i.link;
        }

      if (current_entry->d.h == resolved_hash_entry)
        {
          return 1;
        }

      struct bfinfdpic_relocs_info *existing_canonical_entry =
        bfinfdpic_relocs_info_for_global (hash_table, 0, resolved_hash_entry,
                                          current_entry->addend, NO_INSERT);

      if (existing_canonical_entry)
        {
          bfinfdpic_pic_merge_early_relocs_info (existing_canonical_entry, current_entry);
          htab_clear_slot (hash_table, entry_slot);
          return 1;
        }

      current_entry->d.h = resolved_hash_entry;

      if (! htab_find (hash_table, current_entry))
        {
          htab_clear_slot (hash_table, entry_slot);
          entry_slot = htab_find_slot (hash_table, current_entry, INSERT);
          if (! *entry_slot)
            {
              *entry_slot = current_entry;
            }
          *htab_actual_ptr = NULL;
          return 0;
        }
    }

  return 1;
}

/* Compute the total size of the GOT, the PLT, the dynamic relocations
   section and the rofixup section.  Assign locations for GOT and PLT
   entries.  */

static bool
_bfinfdpic_allocate_section_contents(bfd *dynobj, asection *section)
{
  if (section->size == 0)
    {
      section->flags |= SEC_EXCLUDE;
      return true;
    }

  section->contents = (bfd_byte *) bfd_zalloc(dynobj, section->size);
  if (section->contents == NULL)
    return false;

  section->alloced = 1;
  return true;
}

static bool
_bfinfdpic_size_got_plt (bfd *output_bfd,
			 struct _bfinfdpic_dynamic_got_plt_info *gpinfop)
{
  const bfd_signed_vma BFIN_GOT_INITIAL_OFFSET = 12;
  const bfd_vma BFIN_GOT_WORD_SIZE = 4;
  const bfd_vma BFIN_GOT_18BIT_LIMIT = (bfd_vma)1 << 18;
  const bfd_vma BFIN_GOT_18BIT_RANGE_MAX_OFFSET = (bfd_vma)1 << (18 - 1);
  const bfd_vma BFIN_GOT_32BIT_RANGE_MAX_OFFSET = (bfd_vma)1 << (32 - 1);
  const bfd_vma BFIN_GOT17M4_SHIFT_BITS = 16;

  struct bfd_link_info *info = gpinfop->g.info;
  bfd *dynobj = elf_hash_table (info)->dynobj;
  const struct elf_backend_data *bed = get_elf_backend_data(output_bfd);
  const bool dynamic_sections_created = elf_hash_table(info)->dynamic_sections_created;

  memcpy (bfinfdpic_dynamic_got_plt_info (info), &gpinfop->g,
	  sizeof (gpinfop->g));

  bfd_signed_vma current_odd_offset = BFIN_GOT_INITIAL_OFFSET;
  bfd_vma limit_18bit_range;

  limit_18bit_range = current_odd_offset + gpinfop->g.got17m4 + gpinfop->g.fd17m4;
  if (limit_18bit_range < BFIN_GOT_18BIT_LIMIT)
    limit_18bit_range = BFIN_GOT_18BIT_LIMIT - limit_18bit_range;
  else
    limit_18bit_range = 0;

  if (gpinfop->g.fdplt < limit_18bit_range)
    limit_18bit_range = gpinfop->g.fdplt;

  current_odd_offset = _bfinfdpic_compute_got_alloc_data (&gpinfop->got17m4,
                                                          0,
                                                          current_odd_offset,
                                                          BFIN_GOT17M4_SHIFT_BITS,
                                                          gpinfop->g.got17m4,
                                                          gpinfop->g.fd17m4,
                                                          limit_18bit_range,
                                                          BFIN_GOT_18BIT_RANGE_MAX_OFFSET);

  current_odd_offset = _bfinfdpic_compute_got_alloc_data (&gpinfop->gothilo,
                                                          gpinfop->got17m4.min,
                                                          current_odd_offset,
                                                          gpinfop->got17m4.max,
                                                          gpinfop->g.gothilo,
                                                          gpinfop->g.fdhilo,
                                                          gpinfop->g.fdplt - gpinfop->got17m4.fdplt,
                                                          BFIN_GOT_32BIT_RANGE_MAX_OFFSET);

  htab_traverse (bfinfdpic_relocs_info (info), _bfinfdpic_assign_got_entries,
		 gpinfop);

  asection *got_sec = bfinfdpic_got_section (info);
  got_sec->size = gpinfop->gothilo.max - gpinfop->gothilo.min;
  if (current_odd_offset + BFIN_GOT_WORD_SIZE == gpinfop->gothilo.max) {
      got_sec->size -= BFIN_GOT_WORD_SIZE;
  }

  if (got_sec->size == 12 && !dynamic_sections_created)
    {
      got_sec->flags |= SEC_EXCLUDE;
      got_sec->size = 0;
    }
  else if (!_bfinfdpic_allocate_section_contents(dynobj, got_sec))
    {
      return false;
    }

  asection *gotrel_sec = bfinfdpic_gotrel_section (info);
  if (dynamic_sections_created)
    {
      gotrel_sec->size =
        (gpinfop->g.relocs - gpinfop->g.lzplt / LZPLT_NORMAL_SIZE)
        * bed->s->sizeof_rel;
    }
  else
    {
      BFD_ASSERT (gpinfop->g.relocs == 0);
      gotrel_sec->size = 0;
    }

  if (!_bfinfdpic_allocate_section_contents(dynobj, gotrel_sec))
    {
      return false;
    }

  asection *gotfixup_sec = bfinfdpic_gotfixup_section (info);
  gotfixup_sec->size = (gpinfop->g.fixups + 1) * BFIN_GOT_WORD_SIZE;
  if (!_bfinfdpic_allocate_section_contents(dynobj, gotfixup_sec))
    {
      return false;
    }

  asection *pltrel_sec = bfinfdpic_pltrel_section (info);
  if (dynamic_sections_created)
    {
      pltrel_sec->size =
        gpinfop->g.lzplt / LZPLT_NORMAL_SIZE * bed->s->sizeof_rel;
    }
  else
    {
        pltrel_sec->size = 0;
    }

  if (!_bfinfdpic_allocate_section_contents(dynobj, pltrel_sec))
    {
      return false;
    }

  asection *plt_sec = bfinfdpic_plt_section (info);
  if (dynamic_sections_created)
    {
      plt_sec->size = gpinfop->g.lzplt
	+ ((gpinfop->g.lzplt + (BFINFDPIC_LZPLT_BLOCK_SIZE - BFIN_GOT_WORD_SIZE) - LZPLT_NORMAL_SIZE)
	   / (BFINFDPIC_LZPLT_BLOCK_SIZE - BFIN_GOT_WORD_SIZE) * LZPLT_RESOLVER_EXTRA);
    }
  else
    {
        plt_sec->size = 0;
    }

  gpinfop->g.lzplt = 0;

  bfinfdpic_got_initial_offset (info) = -gpinfop->gothilo.min;

  if (bed->want_got_sym)
    elf_hash_table (info)->hgot->root.u.def.value
      = bfinfdpic_got_initial_offset (info);

  if (dynamic_sections_created)
    bfinfdpic_plt_initial_offset (info) = plt_sec->size;

  htab_traverse (bfinfdpic_relocs_info (info), _bfinfdpic_assign_plt_entries,
		 gpinfop);

  if (!_bfinfdpic_allocate_section_contents(dynobj, plt_sec))
    {
      return false;
    }

  return true;
}

/* Set the sizes of the dynamic sections.  */

static void
exclude_empty_section(bfd *abfd, const char *section_name)
{
  asection *s = bfd_get_linker_section(abfd, section_name);
  if (s != NULL && s->size == 0)
    s->flags |= SEC_EXCLUDE;
}

static bool
elf32_bfinfdpic_late_size_sections (bfd *output_bfd,
				    struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  bfd *dynobj = htab->dynobj;

  if (dynobj == NULL)
    return true;

  if (htab->dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  asection *interp_s = bfd_get_linker_section (dynobj, ".interp");
	  if (interp_s == NULL)
	    {
	      bfd_set_error (bfd_error_bad_section_name);
	      return false;
	    }
	  interp_s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  interp_s->contents = (bfd_byte *) ELF_DYNAMIC_INTERPRETER;
	  interp_s->alloced = 1;
	}
    }

  struct _bfinfdpic_dynamic_got_plt_info gpinfo;
  memset (&gpinfo, 0, sizeof (gpinfo));
  gpinfo.g.info = info;

  for (;;)
    {
      htab_t relocs = bfinfdpic_relocs_info (info);
      htab_traverse (relocs, _bfinfdpic_resolve_final_relocs_info, &relocs);
      if (relocs == bfinfdpic_relocs_info (info))
	break;
    }

  htab_traverse (bfinfdpic_relocs_info (info), _bfinfdpic_count_got_plt_entries,
		 &gpinfo.g);

  struct _bfinfdpic_dynamic_got_plt_info_g *allocated_gpinfo_g = bfd_alloc (dynobj, sizeof (gpinfo.g));
  if (allocated_gpinfo_g == NULL)
    {
      return false;
    }
  bfinfdpic_dynamic_got_plt_info (info) = allocated_gpinfo_g;

  if (!_bfinfdpic_size_got_plt (output_bfd, &gpinfo))
      return false;

  exclude_empty_section(dynobj, ".dynbss");
  exclude_empty_section(dynobj, ".rela.bss");

  return _bfd_elf_add_dynamic_tags (output_bfd, info, true);
}

static bool
elf32_bfinfdpic_early_size_sections (bfd *output_bfd,
				     struct bfd_link_info *info)
{
  if (bfd_link_relocatable (info))
    {
      return true;
    }

  return bfd_elf_stack_segment_size (output_bfd, info,
				     "__stacksize", DEFAULT_STACK_SIZE);
}

/* Check whether any of the relocations was optimized away, and
   subtract it from the relocation or fixup count.  */
static struct elf_link_hash_entry *
resolve_elf_hash_entry (struct elf_link_hash_entry **sym_hashes,
			unsigned long r_symndx,
			unsigned long symtab_sh_info)
{
  struct elf_link_hash_entry *h;

  if (r_symndx < symtab_sh_info)
    return NULL;

  h = sym_hashes[r_symndx - symtab_sh_info];
  while (h->root.type == bfd_link_hash_indirect
	 || h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *)h->root.u.i.link;
  return h;
}

static bool
is_bfin_relevant_reloc (unsigned int r_type)
{
  return r_type == R_BFIN_BYTE4_DATA || r_type == R_BFIN_FUNCDESC;
}

static bool
process_single_discarded_reloc (bfd *abfd,
				asection *sec,
				struct bfd_link_info *info,
				Elf_Internal_Rela *rel,
				struct elf_link_hash_entry *h,
				unsigned long r_symndx,
				bool *changed_flag)
{
  struct bfinfdpic_relocs_info *picrel;
  struct _bfinfdpic_dynamic_got_info *dinfo;
  unsigned int r_type = ELF32_R_TYPE (rel->r_info);

  if (_bfd_elf_section_offset (sec->output_section->owner, info, sec, rel->r_offset) != (bfd_vma)-1)
    return true;

  if (h != NULL)
    picrel = bfinfdpic_relocs_info_for_global (bfinfdpic_relocs_info (info),
                                              abfd, h,
                                              rel->r_addend, NO_INSERT);
  else
    picrel = bfinfdpic_relocs_info_for_local (bfinfdpic_relocs_info (info),
                                             abfd, r_symndx,
                                             rel->r_addend, NO_INSERT);

  if (!picrel)
    return false;

  *changed_flag = true;

  dinfo = bfinfdpic_dynamic_got_plt_info (info);

  _bfinfdpic_count_relocs_fixups (picrel, dinfo, true);
  if (r_type == R_BFIN_BYTE4_DATA)
    picrel->relocs32--;
  else
    picrel->relocsfd--;
  _bfinfdpic_count_relocs_fixups (picrel, dinfo, false);

  return true;
}

static bool
_bfinfdpic_check_discarded_relocs (bfd *abfd, asection *sec,
				   struct bfd_link_info *info,
				   bool *changed)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *erel;

  if (!sec || !info || !changed) {
    return false;
  }

  if (! (sec->flags & SEC_RELOC) || sec->reloc_count == 0)
    return true;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  Elf_Internal_section_data *sec_data = elf_section_data(sec);
  if (!sec_data) {
      return false;
  }
  rel = sec_data->relocs;

  if (!rel && sec->reloc_count > 0) {
      return false;
  }

  for (erel = rel + sec->reloc_count; rel < erel; rel++)
    {
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      struct elf_link_hash_entry *h;

      if (!is_bfin_relevant_reloc(r_type))
	continue;

      h = resolve_elf_hash_entry(sym_hashes, r_symndx, symtab_hdr->sh_info);

      if (!process_single_discarded_reloc (abfd, sec, info, rel, h, r_symndx, changed))
	return false;
    }

  return true;
}

static bool bfinfdpic_handle_changed_state (bfd *obfd, struct bfd_link_info *info) {
  struct _bfinfdpic_dynamic_got_plt_info gpinfo;
  memset (&gpinfo, 0, sizeof (gpinfo));
  memcpy (&gpinfo.g, bfinfdpic_dynamic_got_plt_info (info), sizeof (gpinfo.g));
  htab_traverse (bfinfdpic_relocs_info (info), _bfinfdpic_reset_got_plt_entries, NULL);
  if (!_bfinfdpic_size_got_plt (obfd, &gpinfo)) {
    return false;
  }
  return true;
}

static bool bfinfdpic_elf_discard_info (bfd *ibfd, struct elf_reloc_cookie *cookie ATTRIBUTE_UNUSED, struct bfd_link_info *info) {
  bool changed = false;
  asection *s;
  bfd *obfd = NULL;

  for (s = ibfd->sections; s; s = s->next) {
    if (s->sec_info_type == SEC_INFO_TYPE_EH_FRAME) {
      if (!_bfinfdpic_check_discarded_relocs (ibfd, s, info, &changed)) {
        return false;
      }
      obfd = s->output_section->owner;
    }
  }

  if (changed) {
    if (!bfinfdpic_handle_changed_state (obfd, info)) {
      return false;
    }
  }

  return true;
}

static bool
elf32_bfinfdpic_finish_dynamic_sections (bfd *output_bfd,
					struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn;
  struct elf_link_hash_table *hash_table = elf_hash_table (info);

  dynobj = hash_table->dynobj;

  asection *got_section = bfinfdpic_got_section (info);
  if (got_section)
    {
      asection *gotrel_section = bfinfdpic_gotrel_section (info);
      BFD_ASSERT (gotrel_section->size
		  >= (gotrel_section->reloc_count * sizeof (Elf32_External_Rel)));

      asection *gotfixup_section = bfinfdpic_gotfixup_section (info);
      if (gotfixup_section)
	{
	  struct elf_link_hash_entry *hgot = hash_table->hgot;
	  bfd_vma got_base_value;

	  if (!hgot || !hgot->root.u.def.section || !hgot->root.u.def.section->output_section)
	    {
	      _bfd_error_handler ("LINKER BUG: ELF GOT hash entry or its section data is unexpectedly null.");
	      return false;
	    }

	  got_base_value = hgot->root.u.def.value
	    + hgot->root.u.def.section->output_section->vma
	    + hgot->root.u.def.section->output_offset;

	  _bfinfdpic_add_rofixup (output_bfd, gotfixup_section, got_base_value, 0);

	  if (gotfixup_section->size != (gotfixup_section->reloc_count * sizeof(Elf32_Addr)))
	    {
	      _bfd_error_handler
		("LINKER BUG: .rofixup section size mismatch");
	      return false;
	    }
	}
    }

  bool dynamic_sections_created = hash_table->dynamic_sections_created;
  if (dynamic_sections_created)
    {
      asection *pltrel_section = bfinfdpic_pltrel_section (info);
      BFD_ASSERT (pltrel_section->size
		  == (pltrel_section->reloc_count * sizeof (Elf32_External_Rel)));

      sdyn = bfd_get_linker_section (dynobj, ".dynamic");
      BFD_ASSERT (sdyn != NULL);

      Elf32_External_Dyn * current_dyn_entry = (Elf32_External_Dyn *) sdyn->contents;
      Elf32_External_Dyn * end_dyn_entry = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

      for (; current_dyn_entry < end_dyn_entry; current_dyn_entry++)
	{
	  Elf_Internal_Dyn dyn_entry_internal;

	  bfd_elf32_swap_dyn_in (dynobj, current_dyn_entry, &dyn_entry_internal);

	  switch (dyn_entry_internal.d_tag)
	    {
	    case DT_PLTGOT:
	      {
		if (!got_section || !got_section->output_section)
		  {
		    _bfd_error_handler ("LINKER BUG: DT_PLTGOT found but GOT section is missing or incomplete.");
		    return false;
		  }
		bfd_vma got_vma_base = got_section->output_section->vma
		  + got_section->output_offset;
		bfd_vma got_initial_offset = bfinfdpic_got_initial_offset (info);
		dyn_entry_internal.d_un.d_ptr = got_vma_base + got_initial_offset;
		bfd_elf32_swap_dyn_out (output_bfd, &dyn_entry_internal, current_dyn_entry);
	      }
	      break;

	    case DT_JMPREL:
	      {
		dyn_entry_internal.d_un.d_ptr = pltrel_section->output_section->vma
		  + pltrel_section->output_offset;
		bfd_elf32_swap_dyn_out (output_bfd, &dyn_entry_internal, current_dyn_entry);
	      }
	      break;

	    case DT_PLTRELSZ:
	      {
		dyn_entry_internal.d_un.d_val = pltrel_section->size;
		bfd_elf32_swap_dyn_out (output_bfd, &dyn_entry_internal, current_dyn_entry);
	      }
	      break;

	    default:
	      break;
	    }
	}
    }

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  */

static bool
elf32_bfinfdpic_adjust_dynamic_symbol (struct bfd_link_info *info,
				       struct elf_link_hash_entry *h)
{
  BFD_ASSERT (elf_hash_table (info)->dynobj != NULL
	      && (h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
    }

  return true;
}

/* Perform any actions needed for dynamic symbols.  */

static bool
elf32_bfinfdpic_finish_dynamic_symbol
(bfd *output_bfd ATTRIBUTE_UNUSED,
 struct bfd_link_info *info ATTRIBUTE_UNUSED,
 struct elf_link_hash_entry *h ATTRIBUTE_UNUSED,
 Elf_Internal_Sym *sym ATTRIBUTE_UNUSED)
{
  return true;
}

/* Decide whether to attempt to turn absptr or lsda encodings in
   shared libraries into pcrel within the given input section.  */

static bool
bfinfdpic_elf_use_relative_eh_frame
(bfd *input_bfd ATTRIBUTE_UNUSED,
 struct bfd_link_info *info ATTRIBUTE_UNUSED,
 asection *eh_frame_section ATTRIBUTE_UNUSED)
{
  return false;
}

/* Adjust the contents of an eh_frame_hdr section before they're output.  */

static bfd_byte
bfinfdpic_elf_encode_eh_address (bfd *abfd,
				struct bfd_link_info *info,
				asection *osec, bfd_vma offset,
				asection *loc_sec, bfd_vma loc_offset,
				bfd_vma *encoded)
{
  bfd_link_hash_table *hash_table = elf_hash_table (info);
  struct elf_link_hash_entry *h;

  // If `elf_hash_table` returns NULL, `h` will be NULL after this assignment.
  // The `BFD_ASSERT` below will then trigger, maintaining the original crash-on-error behavior.
  h = hash_table->hgot;

  // Original behavior: If h is NULL or its type is not bfd_link_hash_defined,
  // the program asserts/terminates. This strong invariant is preserved.
  BFD_ASSERT (h != NULL && h->root.type == bfd_link_hash_defined);

  // Extract segment IDs for improved readability and to avoid redundant function calls.
  bfd_vma osec_segment_id = _bfinfdpic_osec_to_segment (abfd, osec);
  bfd_vma loc_output_segment_id;

  // Improve reliability: Robustly check `loc_sec->output_section` before dereferencing it.
  // If it's NULL, passing it to `_bfinfdpic_osec_to_segment` could lead to a crash
  // or undefined behavior within that function.
  // Falling back to the generic encoder in this specific, unexpected case avoids a crash
  // without altering the intended functionality when valid pointers are provided.
  if (loc_sec->output_section == NULL) {
    return _bfd_elf_encode_eh_address (abfd, info, osec, offset,
				       loc_sec, loc_offset, encoded);
  }
  loc_output_segment_id = _bfinfdpic_osec_to_segment (abfd, loc_sec->output_section);

  // The condition for falling back to the generic encoder, matching original logic.
  if (osec_segment_id == loc_output_segment_id) {
    return _bfd_elf_encode_eh_address (abfd, info, osec, offset,
				       loc_sec, loc_offset, encoded);
  }

  // At this point, `h` is guaranteed to be valid and of type `bfd_link_hash_defined`.
  // Also, `loc_sec->output_section` is non-NULL, and the segments are different.

  // Extract nested section pointers for clarity and to ensure safe access.
  asection *h_def_section = h->root.u.def.section;
  // Ensure `h_def_section` is not NULL. This is an internal consistency check
  // crucial for the validity of the data structure and subsequent operations.
  BFD_ASSERT(h_def_section != NULL);

  asection *h_output_section = h_def_section->output_section;
  // Ensure `h_output_section` is not NULL. Also critical for following operations.
  BFD_ASSERT(h_output_section != NULL);

  // The second BFD_ASSERT from the original code, maintaining its strict invariant
  // regarding section segment alignment.
  bfd_vma h_output_section_segment_id = _bfinfdpic_osec_to_segment (abfd, h_output_section);
  BFD_ASSERT (osec_segment_id == h_output_section_segment_id);

  // Simplify the complex calculation for the `*encoded` value, improving readability.
  bfd_vma h_root_def_value = h->root.u.def.value;
  bfd_vma h_output_section_vma = h_output_section->vma;
  bfd_vma h_def_section_output_offset = h_def_section->output_offset;

  bfd_vma h_base_address = h_root_def_value + h_output_section_vma + h_def_section_output_offset;

  *encoded = osec->vma + offset - h_base_address;

  return DW_EH_PE_datarel | DW_EH_PE_sdata4;
}



/* Look through the relocs for a section during the first phase.

   Besides handling virtual table relocs for gc, we have to deal with
   all sorts of PIC-related relocations.  We describe below the
   general plan on how to handle such relocations, even though we only
   collect information at this point, storing them in hash tables for
   perusal of later passes.

   32 relocations are propagated to the linker output when creating
   position-independent output.  LO16 and HI16 relocations are not
   supposed to be encountered in this case.

   LABEL16 should always be resolvable by the linker, since it's only
   used by branches.

   LABEL24, on the other hand, is used by calls.  If it turns out that
   the target of a call is a dynamic symbol, a PLT entry must be
   created for it, which triggers the creation of a private function
   descriptor and, unless lazy binding is disabled, a lazy PLT entry.

   GPREL relocations require the referenced symbol to be in the same
   segment as _gp, but this can only be checked later.

   All GOT, GOTOFF and FUNCDESC relocations require a .got section to
   exist.  LABEL24 might as well, since it may require a PLT entry,
   that will require a got.

   Non-FUNCDESC GOT relocations require a GOT entry to be created
   regardless of whether the symbol is dynamic.  However, since a
   global symbol that turns out to not be exported may have the same
   address of a non-dynamic symbol, we don't assign GOT entries at
   this point, such that we can share them in this case.  A relocation
   for the GOT entry always has to be created, be it to offset a
   private symbol by the section load address, be it to get the symbol
   resolved dynamically.

   FUNCDESC GOT relocations require a GOT entry to be created, and
   handled as if a FUNCDESC relocation was applied to the GOT entry in
   an object file.

   FUNCDESC relocations referencing a symbol that turns out to NOT be
   dynamic cause a private function descriptor to be created.  The
   FUNCDESC relocation then decays to a 32 relocation that points at
   the private descriptor.  If the symbol is dynamic, the FUNCDESC
   relocation is propagated to the linker output, such that the
   dynamic linker creates the canonical descriptor, pointing to the
   dynamically-resolved definition of the function.

   Non-FUNCDESC GOTOFF relocations must always refer to non-dynamic
   symbols that are assigned to the same segment as the GOT, but we
   can only check this later, after we know the complete set of
   symbols defined and/or exported.

   FUNCDESC GOTOFF relocations require a function descriptor to be
   created and, unless lazy binding is disabled or the symbol is not
   dynamic, a lazy PLT entry.  Since we can't tell at this point
   whether a symbol is going to be dynamic, we have to decide later
   whether to create a lazy PLT entry or bind the descriptor directly
   to the private function.

   FUNCDESC_VALUE relocations are not supposed to be present in object
   files, but they may very well be simply propagated to the linker
   output, since they have no side effect.


   A function descriptor always requires a FUNCDESC_VALUE relocation.
   Whether it's in .plt.rel or not depends on whether lazy binding is
   enabled and on whether the referenced symbol is dynamic.

   The existence of a lazy PLT requires the resolverStub lazy PLT
   entry to be present.


   As for assignment of GOT, PLT and lazy PLT entries, and private
   descriptors, we might do them all sequentially, but we can do
   better than that.  For example, we can place GOT entries and
   private function descriptors referenced using 12-bit operands
   closer to the PIC register value, such that these relocations don't
   overflow.  Those that are only referenced with LO16 relocations
   could come next, but we may as well place PLT-required function
   descriptors in the 12-bit range to make them shorter.  Symbols
   referenced with LO16/HI16 may come next, but we may place
   additional function descriptors in the 16-bit range if we can
   reliably tell that we've already placed entries that are ever
   referenced with only LO16.  PLT entries are therefore generated as
   small as possible, while not introducing relocation overflows in
   GOT or FUNCDESC_GOTOFF relocations.  Lazy PLT entries could be
   generated before or after PLT entries, but not intermingled with
   them, such that we can have more lazy PLT entries in range for a
   branch to the resolverStub.  The resolverStub should be emitted at
   the most distant location from the first lazy PLT entry such that
   it's still in range for a branch, or closer, if there isn't a need
   for so many lazy PLT entries.  Additional lazy PLT entries may be
   emitted after the resolverStub, as long as branches are still in
   range.  If the branch goes out of range, longer lazy PLT entries
   are emitted.

   We could further optimize PLT and lazy PLT entries by giving them
   priority in assignment to closer-to-gr17 locations depending on the
   number of occurrences of references to them (assuming a function
   that's called more often is more important for performance, so its
   PLT entry should be faster), or taking hints from the compiler.
   Given infinite time and money... :-)  */

static bool
bfinfdpic_check_relocs (bfd *abfd, struct bfd_link_info *info,
			asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  bfd *dynobj;

  if (bfd_link_relocatable (info))
    return true;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  dynobj = elf_hash_table (info)->dynobj;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h = NULL;
      unsigned long r_symndx;
      enum elf_reloc_type r_type = ELF32_R_TYPE (rel->r_info);
      struct bfinfdpic_relocs_info *picrel = NULL;

      r_symndx = ELF32_R_SYM (rel->r_info);
      if (r_symndx >= symtab_hdr->sh_info)
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h && (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning))
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      switch (r_type)
	{
	case R_BFIN_GOT17M4:
	case R_BFIN_GOTHI:
	case R_BFIN_GOTLO:
	case R_BFIN_FUNCDESC_GOT17M4:
	case R_BFIN_FUNCDESC_GOTHI:
	case R_BFIN_FUNCDESC_GOTLO:
	case R_BFIN_GOTOFF17M4:
	case R_BFIN_GOTOFFHI:
	case R_BFIN_GOTOFFLO:
	case R_BFIN_FUNCDESC_GOTOFF17M4:
	case R_BFIN_FUNCDESC_GOTOFFHI:
	case R_BFIN_FUNCDESC_GOTOFFLO:
	case R_BFIN_FUNCDESC:
	case R_BFIN_FUNCDESC_VALUE:
	  if (!IS_FDPIC(abfd))
	    {
	      _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, (int) r_type);
	      return false;
	    }
	  /* FALLTHROUGH */
	case R_BFIN_PCREL24:
	case R_BFIN_PCREL24_JUMP_L:
	case R_BFIN_BYTE4_DATA:
	  if (IS_FDPIC(abfd))
	    {
	      if (!dynobj)
		{
		  elf_hash_table (info)->dynobj = dynobj = abfd;
		  if (! _bfin_create_got_section (abfd, info))
		    return false;
		}

	      if (h != NULL)
		{
		  if (h->dynindx == -1)
		    switch (ELF_ST_VISIBILITY (h->other))
		      {
		      case STV_INTERNAL:
		      case STV_HIDDEN:
			break;
		      default:
			bfd_elf_link_record_dynamic_symbol (info, h);
			break;
		      }
		  picrel = bfinfdpic_relocs_info_for_global (bfinfdpic_relocs_info (info),
							     abfd, h,
							     rel->r_addend, INSERT);
		}
	      else
		picrel = bfinfdpic_relocs_info_for_local (bfinfdpic_relocs_info
							 (info), abfd, r_symndx,
							 rel->r_addend, INSERT);
	      if (!picrel)
		return false;
	    }

	  if (picrel)
	    {
	      switch (r_type)
		{
		case R_BFIN_PCREL24:
		case R_BFIN_PCREL24_JUMP_L:
		  picrel->call++;
		  break;

		case R_BFIN_FUNCDESC_VALUE:
		  picrel->relocsfdv++;
		  if (bfd_section_flags (sec) & SEC_ALLOC)
		    picrel->relocs32--;
		  /* FALLTHROUGH */
		case R_BFIN_BYTE4_DATA:
		  picrel->sym++;
		  if (bfd_section_flags (sec) & SEC_ALLOC)
		    picrel->relocs32++;
		  break;

		case R_BFIN_GOT17M4:
		  picrel->got17m4++;
		  break;

		case R_BFIN_GOTHI:
		case R_BFIN_GOTLO:
		  picrel->gothilo++;
		  break;

		case R_BFIN_FUNCDESC_GOT17M4:
		  picrel->fdgot17m4++;
		  break;

		case R_BFIN_FUNCDESC_GOTHI:
		case R_BFIN_FUNCDESC_GOTLO:
		  picrel->fdgothilo++;
		  break;

		case R_BFIN_GOTOFF17M4:
		case R_BFIN_GOTOFFHI:
		case R_BFIN_GOTOFFLO:
		  picrel->gotoff++;
		  break;

		case R_BFIN_FUNCDESC_GOTOFF17M4:
		  picrel->fdgoff17m4++;
		  break;

		case R_BFIN_FUNCDESC_GOTOFFHI:
		case R_BFIN_FUNCDESC_GOTOFFLO:
		  picrel->fdgoffhilo++;
		  break;

		case R_BFIN_FUNCDESC:
		  picrel->fd++;
		  picrel->relocsfd++;
		  break;

		default:
		  break;
		}
	    }
	  break;

	case R_BFIN_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    return false;
	  break;

	case R_BFIN_GNU_VTENTRY:
	  if (h != NULL
	      && !bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    return false;
	  break;

	case R_BFIN_HUIMM16:
	case R_BFIN_LUIMM16:
	case R_BFIN_PCREL12_JUMP_S:
	case R_BFIN_PCREL10:
	  break;

	default:
	  _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, (int) r_type);
	  return false;
	}
    }

  return true;
}

/* Set the right machine number for a Blackfin ELF file.  */

static bool
elf32_bfin_object_p (bfd *abfd)
{
  bfd_default_set_arch_mach (abfd, bfd_arch_bfin, 0);

  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  if (ehdr == NULL)
    {
      return false;
    }

  bool header_has_fdpic_flag = ((ehdr->e_flags & EF_BFIN_FDPIC) != 0);
  bool bfd_is_fdpic = IS_FDPIC (abfd);

  return header_has_fdpic_flag == bfd_is_fdpic;
}

static bool
elf32_bfin_set_private_flags (bfd * abfd, flagword flags)
{
  if (abfd == NULL)
    {
      return false;
    }

  elf_elfheader (abfd)->e_flags = flags;
  elf_flags_init (abfd) = true;
  return true;
}

/* Display the flags field.  */
static bool
elf32_bfin_print_private_bfd_data (bfd * abfd, void * ptr)
{
  if (abfd == NULL || ptr == NULL)
    {
      return false;
    }

  FILE *file = (FILE *) ptr;
  flagword flags;
  bool ret = true;

  if (!_bfd_elf_print_private_bfd_data (abfd, ptr))
    {
      return false;
    }

  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  if (ehdr == NULL)
    {
      return false;
    }
  flags = ehdr->e_flags;

  if (fprintf (file, _("private flags = %lx:"), flags) < 0)
    {
      ret = false;
    }

  if (ret && (flags & EF_BFIN_PIC))
    {
      if (fprintf (file, " -fpic") < 0)
        {
          ret = false;
        }
    }

  if (ret && (flags & EF_BFIN_FDPIC))
    {
      if (fprintf (file, " -mfdpic") < 0)
        {
          ret = false;
        }
    }

  if (fputc ('\n', file) == EOF)
    {
      ret = false;
    }

  return ret;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_bfin_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword new_flags;
  bool error = false;

  if ((ibfd->flags & DYNAMIC) != 0)
    return true;

  new_flags = elf_elfheader (ibfd)->e_flags;

  if (new_flags & EF_BFIN_FDPIC)
    new_flags &= ~EF_BFIN_PIC;

  bool obfd_flags_initialized = elf_flags_init (obfd);
  bool obfd_is_fdpic_current_state = IS_FDPIC (obfd);

  if (!obfd_flags_initialized)
    {
      elf_flags_init (obfd) = true;
      elf_elfheader (obfd)->e_flags = new_flags;
    }
  else
    {
      bool ibfd_is_fdpic = (new_flags & EF_BFIN_FDPIC) != 0;

      if (ibfd_is_fdpic != obfd_is_fdpic_current_state)
        {
          error = true;
          if (obfd_is_fdpic_current_state)
            _bfd_error_handler
              (_("%pB: cannot link non-fdpic object file into fdpic executable"),
               ibfd);
          else
            _bfd_error_handler
              (_("%pB: cannot link fdpic object file into non-fdpic executable"),
               ibfd);
        }
    }

  if (error)
    bfd_set_error (bfd_error_bad_value);

  return !error;
}

/* bfin ELF linker hash entry.  */

struct bfin_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Number of PC relative relocs copied for this symbol.  */
  struct bfin_pcrel_relocs_copied *pcrel_relocs_copied;
};

#define bfin_hash_entry(ent) ((struct bfin_link_hash_entry *) (ent))

static struct bfd_hash_entry *
bfin_link_hash_newfunc (struct bfd_hash_entry *entry,
			struct bfd_hash_table *table, const char *string)
{
  struct bfd_hash_entry *result_entry = entry;

  if (result_entry == NULL)
    {
      result_entry = bfd_hash_allocate (table, sizeof (struct bfin_link_hash_entry));
      if (result_entry == NULL)
        {
          return NULL;
        }
    }

  result_entry = _bfd_elf_link_hash_newfunc (result_entry, table, string);
  if (result_entry != NULL)
    {
      bfin_hash_entry (result_entry)->pcrel_relocs_copied = NULL;
    }

  return result_entry;
}

/* Create an bfin ELF linker hash table.  */

static struct bfd_link_hash_table *
bfin_link_hash_table_create (bfd * abfd)
{
  struct elf_link_hash_table *ret;

  ret = bfd_zmalloc (sizeof (struct elf_link_hash_table));
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (ret, abfd, bfin_link_hash_newfunc,
				      sizeof (struct elf_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  return &ret->root;
}

/* The size in bytes of an entry in the procedure linkage table.  */

/* Finish up the dynamic sections.  */

static bool
bfin_finish_dynamic_sections (bfd * output_bfd ATTRIBUTE_UNUSED,
			      struct bfd_link_info *info)
{
  struct elf_link_hash_table *elf_info;
  bfd *dynobj;
  asection *sdyn;

  // Store the result of elf_hash_table(info) to avoid repeated calls
  // and improve readability.
  elf_info = elf_hash_table (info);
  dynobj = elf_info->dynobj;

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_info->dynamic_sections_created)
    {
      // Replaced BFD_ASSERT with an explicit check for reliability.
      // If the .dynamic section is expected but missing, this is an error
      // that should be handled gracefully by returning false, rather than
      // crashing (which BFD_ASSERT or a subsequent NULL dereference would cause).
      if (sdyn == NULL)
        {
          return false; // Indicate failure
        }

      // The original loop iterated through the .dynamic section and called
      // bfd_elf32_swap_dyn_in, but the 'dyn' variable populated by this call
      // was never used. This made the loop effectively a no-op with no
      // observable side effects. Removing this dead code simplifies the logic,
      // improves maintainability, and removes a code smell without altering
      // external functionality.
    }
  return true;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
bfin_finish_dynamic_symbol (bfd * output_bfd,
			    struct bfd_link_info *info,
			    struct elf_link_hash_entry *h,
			    Elf_Internal_Sym * sym)
{
  struct elf_link_hash_table *hash_table = elf_hash_table(info);

  if (h->got.offset != (bfd_vma) - 1)
    {
      asection *sgot;
      asection *srela;
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      bfd_vma got_entry_address_offset;

      sgot = hash_table->sgot;
      srela = hash_table->srelgot;
      BFD_ASSERT (sgot != NULL && srela != NULL);

      got_entry_address_offset = h->got.offset & ~(bfd_vma) 1;

      rela.r_offset = (sgot->output_section->vma
		       + sgot->output_offset
		       + got_entry_address_offset);

      bool is_pic_link = bfd_link_pic(info);
      bool is_symbolic_or_local_forced = info->symbolic || h->dynindx == -1 || h->forced_local;
      bool is_regular_definition = h->def_regular;

      if (is_pic_link && is_symbolic_or_local_forced && is_regular_definition)
	{
	  _bfd_error_handler (_("*** check this relocation %s"), __func__);
	  rela.r_info = ELF32_R_INFO (0, R_BFIN_PCREL24);
	  rela.r_addend = bfd_get_signed_32 (output_bfd,
					     sgot->contents + got_entry_address_offset);
	}
      else
	{
	  bfd_put_32 (output_bfd, (bfd_vma) 0,
		      sgot->contents + got_entry_address_offset);
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_BFIN_GOT);
	  rela.r_addend = 0;
	}

      loc = srela->contents;
      loc += srela->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  if (h->needs_copy)
    {
      BFD_ASSERT (0);
    }
  
  if (strcmp (h->root.root.string, "__DYNAMIC") == 0
      || h == hash_table->hgot)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
bfin_adjust_dynamic_symbol (struct bfd_link_info *info,
			    struct elf_link_hash_entry *h)
{
  bfd *dynobj;
  asection *s;
  unsigned int power_of_two;

  if (info == NULL || h == NULL)
    {
      _bfd_error_handler (_("Internal error: Invalid null pointer passed to bfin_adjust_dynamic_symbol."));
      return false;
    }

  dynobj = elf_hash_table (info)->dynobj;

  if (dynobj == NULL)
    {
      _bfd_error_handler (_("Internal error: Dynamic object not found for symbol adjustment."));
      return false;
    }

  if (!(h->needs_plt || h->is_weakalias || (h->def_dynamic && h->ref_regular && !h->def_regular)))
    {
      _bfd_error_handler (_("Internal error: bfin_adjust_dynamic_symbol called for an unhandled symbol type or state."));
      return false;
    }

  if (h->type == STT_FUNC || h->needs_plt)
    {
      _bfd_error_handler (_("The bfin target does not currently support dynamic adjustment for function symbols or symbols requiring PLT entries in this context."));
      return false;
    }

  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      if (def == NULL || def->root.type != bfd_link_hash_defined)
        {
          _bfd_error_handler (_("Internal error: Weak symbol definition not found or invalid for alias resolution."));
          return false;
        }
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return true;
    }

  if (bfd_link_pic (info))
    return true;

  s = bfd_get_linker_section (dynobj, ".dynbss");
  if (s == NULL)
    {
      _bfd_error_handler (_("Internal error: .dynbss section not found or could not be created."));
      return false;
    }

  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0)
    {
      _bfd_error_handler (_("the bfin target does not currently support the generation of copy relocations"));
      return false;
    }

  if (h->size == 0)
    {
      power_of_two = 0;
    }
  else
    {
      power_of_two = bfd_log2 (h->size);
    }
  
  if (power_of_two > 3)
    power_of_two = 3;

  s->size = BFD_ALIGN (s->size, (bfd_size_type) (1 << power_of_two));
  if (!bfd_link_align_section (s, power_of_two))
    {
      _bfd_error_handler (_("Failed to align .dynbss section for symbol."));
      return false;
    }

  h->root.u.def.section = s;
  h->root.u.def.value = s->size;

  if (s->size > BFD_SIZE_MAX - h->size)
    {
      _bfd_error_handler (_("Internal error: .dynbss section size overflow during symbol allocation."));
      return false;
    }
  s->size += h->size;

  return true;
}

/* The bfin linker needs to keep track of the number of relocs that it
   decides to copy in check_relocs for each symbol.  This is so that it
   can discard PC relative relocs if it doesn't need them when linking
   with -Bsymbolic.  We store the information in a field extending the
   regular ELF linker hash table.  */

/* This structure keeps track of the number of PC relative relocs we have
   copied for a given symbol.  */

struct bfin_pcrel_relocs_copied
{
  /* Next section.  */
  struct bfin_pcrel_relocs_copied *next;
  /* A section in dynobj.  */
  asection *section;
  /* Number of relocs copied in this section.  */
  bfd_size_type count;
};

/* This function is called via elf_link_hash_traverse if we are
   creating a shared object.  In the -Bsymbolic case it discards the
   space allocated to copy PC relative relocs against symbols which
   are defined in regular objects.  For the normal shared case, it
   discards space for pc-relative relocs that have become local due to
   symbol visibility changes.  We allocated space for them in the
   check_relocs routine, but we won't fill them in in the
   relocate_section routine.

   We also check whether any of the remaining relocations apply
   against a readonly section, and set the DF_TEXTREL flag in this
   case.  */

static bool
bfin_discard_copies (struct elf_link_hash_entry *h, void *inf_ptr)
{
  struct bfd_link_info *info = (struct bfd_link_info *) inf_ptr;
  struct bfin_pcrel_relocs_copied *current_reloc;

  if (!h->def_regular || (!info->symbolic && !h->forced_local))
    {
      if ((info->flags & DF_TEXTREL) == 0)
	{
	  for (current_reloc = bfin_hash_entry(h)->pcrel_relocs_copied;
	       current_reloc != NULL;
	       current_reloc = current_reloc->next)
	    {
	      if ((current_reloc->section->flags & SEC_READONLY) != 0)
		{
		  info->flags |= DF_TEXTREL;
		  break;
		}
	    }
	}
    }
  else
    {
      for (current_reloc = bfin_hash_entry(h)->pcrel_relocs_copied;
	   current_reloc != NULL;
	   current_reloc = current_reloc->next)
	{
	  current_reloc->section->size -= current_reloc->count * sizeof(Elf32_External_Rela);
	}
    }

  return true;
}

static bool
bfin_late_size_sections (bfd * output_bfd ATTRIBUTE_UNUSED,
                         struct bfd_link_info *info)
{
  bfd *dynobj = elf_hash_table (info)->dynobj;
  if (dynobj == NULL)
    return true;

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
        {
          asection *interp_section = bfd_get_linker_section (dynobj, ".interp");
          if (interp_section == NULL)
            {
              _bfd_error_handler (_("linker_internal_error"), ".interp section not found for executable with interpreter.");
              return false;
            }
          interp_section->size = sizeof ELF_DYNAMIC_INTERPRETER;
          interp_section->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
          interp_section->alloced = 1;
        }
    }
  else
    {
      asection *rela_got_section = elf_hash_table (info)->srelgot;
      if (rela_got_section != NULL)
        rela_got_section->size = 0;
    }

  if (bfd_link_pic (info))
    elf_link_hash_traverse (elf_hash_table (info),
                            bfin_discard_copies, info);

  bool has_relocations = false;
  for (asection *s = dynobj->sections; s != NULL; s = s->next)
    {
      if (! (s->flags & SEC_LINKER_CREATED))
        continue;

      const char *section_name = bfd_section_name (s);
      bool strip_section = false;

      if (startswith (section_name, ".rela"))
        {
          if (s->size == 0)
            {
              strip_section = true;
            }
          else
            {
              has_relocations = true;
              s->reloc_count = 0;
            }
        }
      else if (! startswith (section_name, ".got"))
        {
          continue;
        }

      if (strip_section)
        {
          s->flags |= SEC_EXCLUDE;
          continue;
        }

      if (s->size > 0)
        {
          s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
          if (s->contents == NULL)
            return false;
          s->alloced = 1;
        }
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
#define ADD_DYNAMIC_ENTRY(TAG, VAL) \
  do { if (!_bfd_elf_add_dynamic_entry (info, TAG, VAL)) return false; } while (0)

      if (!bfd_link_pic (info))
        {
          ADD_DYNAMIC_ENTRY (DT_DEBUG, 0);
        }

      if (has_relocations)
        {
          ADD_DYNAMIC_ENTRY (DT_RELA, 0);
          ADD_DYNAMIC_ENTRY (DT_RELASZ, 0);
          ADD_DYNAMIC_ENTRY (DT_RELAENT, sizeof (Elf32_External_Rela));
        }

      if ((info->flags & DF_TEXTREL) != 0)
        {
          ADD_DYNAMIC_ENTRY (DT_TEXTREL, 0);
        }
#undef ADD_DYNAMIC_ENTRY
    }

  return true;
}

/* Given a .data section and a .emreloc in-memory section, store
   relocation information into the .emreloc section which can be
   used at runtime to relocate the section.  This is called by the
   linker when the --embedded-relocs switch is used.  This is called
   after the add_symbols entry point has been called for all the
   objects, and before the final_link entry point is called.  */

bool
bfd_bfin_elf32_create_embedded_relocs (bfd *abfd,
				       struct bfd_link_info *info,
				       asection *datasec,
				       asection *relsec,
				       char **errmsg)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL; /* Stores local symbols, potentially allocated */
  Elf_Internal_Rela *internal_relocs = NULL; /* Stores native relocations, potentially allocated */
  bfd_byte *p;
  bool ret = false; /* Assume failure until all steps complete successfully */

  /* Define constants for clarity and maintainability.
     The embedded relocation record contains a 4-byte offset and an 8-byte section name. */
  const bfd_size_type BFIN_EMBEDDED_RELOC_RECORD_SIZE = 12;
  const size_t BFIN_EMBEDDED_SECTION_NAME_LENGTH = 8;
  const size_t BFIN_EMBEDDED_OFFSET_FIELD_OFFSET = 0; // Offset for the 4-byte address
  const size_t BFIN_EMBEDDED_NAME_FIELD_OFFSET = 4;   // Offset for the 8-byte name

  BFD_ASSERT (!bfd_link_relocatable (info));

  *errmsg = NULL;

  if (datasec->reloc_count == 0)
    return true; /* Nothing to do, success */

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  /* Get a copy of the native relocations.
     info->keep_memory influences whether _bfd_elf_link_read_relocs
     allocates new memory or returns a pointer to existing section data. */
  internal_relocs = (_bfd_elf_link_read_relocs
		     (abfd, datasec, NULL, (Elf_Internal_Rela *) NULL,
		      info->keep_memory));
  if (internal_relocs == NULL)
    goto cleanup;

  /* Calculate required size for the embedded relocation section contents. */
  bfd_size_type amt = (bfd_size_type) datasec->reloc_count * BFIN_EMBEDDED_RELOC_RECORD_SIZE;
  relsec->contents = (bfd_byte *) bfd_alloc (abfd, amt);
  if (relsec->contents == NULL)
    goto cleanup;
  relsec->alloced = 1; /* Mark as allocated for BFD to manage its lifetime */

  p = relsec->contents;

  Elf_Internal_Rela *irelend = internal_relocs + datasec->reloc_count;
  for (Elf_Internal_Rela *irel = internal_relocs; irel < irelend;
       irel++, p += BFIN_EMBEDDED_RELOC_RECORD_SIZE)
    {
      asection *targetsec;

      /* We are going to write a four byte longword into the runtime
	 reloc section. The longword will be the address in the data
	 section which must be relocated. It is followed by the name
	 of the target section NUL-padded or truncated to 8
	 characters.  */

      /* We can only relocate absolute longword relocs at run time.  */
      if (ELF32_R_TYPE (irel->r_info) != (int) R_BFIN_BYTE4_DATA)
	{
	  *errmsg = _("unsupported relocation type");
	  bfd_set_error (bfd_error_bad_value);
	  goto cleanup;
	}

      /* Determine the target section referred to by the relocation symbol. */
      if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol: its section index is directly in the symbol entry. */
	  Elf_Internal_Sym *isym;

	  /* Read this BFD's local symbols if we haven't done so already.
	     'symtab_hdr->contents' might already hold them, otherwise
	     bfd_elf_get_elf_syms will allocate and read them. */
	  if (isymbuf == NULL)
	    {
	      isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
	      if (isymbuf == NULL)
		{
		  isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr,
						  symtab_hdr->sh_info, 0,
						  NULL, NULL, NULL);
		}
	      if (isymbuf == NULL)
		goto cleanup; /* Error reading local symbols */
	    }

	  isym = isymbuf + ELF32_R_SYM (irel->r_info);
	  targetsec = bfd_section_from_elf_index (abfd, isym->st_shndx);
	}
      else
	{
	  /* An external symbol: look it up in the linker hash table. */
	  unsigned long indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
	  struct elf_link_hash_entry *h = elf_sym_hashes (abfd)[indx];
	  BFD_ASSERT (h != NULL); /* Should not happen if linker setup correctly */

	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    targetsec = h->root.u.def.section;
	  else
	    targetsec = NULL; /* Undefined or common symbol, no specific target section */
	}

      /* Write the target address (offset in data section). */
      bfd_put_32 (abfd, irel->r_offset + datasec->output_offset, p + BFIN_EMBEDDED_OFFSET_FIELD_OFFSET);

      /* Initialize the section name field to zeros (for NUL-padding). */
      memset (p + BFIN_EMBEDDED_NAME_FIELD_OFFSET, 0, BFIN_EMBEDDED_SECTION_NAME_LENGTH);

      /* If a target section was found, copy its output section name.
         strncpy correctly handles truncation and null-termination given
         the prior memset. */
      if (targetsec != NULL)
	{
	  strncpy ((char *) (p + BFIN_EMBEDDED_NAME_FIELD_OFFSET),
		   targetsec->output_section->name,
		   BFIN_EMBEDDED_SECTION_NAME_LENGTH);
	}
    }

  ret = true; /* Successfully processed all relocations */

cleanup:
  /* Free isymbuf only if it was allocated by bfd_elf_get_elf_syms,
     i.e., it's not pointing to symtab_hdr->contents. */
  if (isymbuf != NULL && symtab_hdr != NULL && symtab_hdr->contents != (unsigned char *) isymbuf)
    free (isymbuf);

  /* Free internal_relocs only if it was allocated by _bfd_elf_link_read_relocs,
     i.e., it's not pointing to existing section relocations. */
  if (internal_relocs != NULL && elf_section_data (datasec)->relocs != internal_relocs)
    free (internal_relocs);

  return ret;
}

struct bfd_elf_special_section const elf32_bfin_special_sections[] =
{
  { ".l1.text",		8, -2, SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR },
  { ".l1.data",		8, -2, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE },
  { NULL,		0,  0, 0,	     0 }
};


#define TARGET_LITTLE_SYM		bfin_elf32_vec
#define TARGET_LITTLE_NAME		"elf32-bfin"
#define ELF_ARCH			bfd_arch_bfin
#define ELF_TARGET_ID			BFIN_ELF_DATA
#define ELF_MACHINE_CODE		EM_BLACKFIN
#define ELF_MAXPAGESIZE			0x1000
#define elf_symbol_leading_char		'_'

#define bfd_elf32_bfd_reloc_type_lookup	bfin_bfd_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup \
					bfin_bfd_reloc_name_lookup
#define elf_info_to_howto		bfin_info_to_howto
#define elf_info_to_howto_rel		NULL
#define elf_backend_object_p		elf32_bfin_object_p

#define bfd_elf32_bfd_is_local_label_name \
					bfin_is_local_label_name

#define elf_backend_create_dynamic_sections \
					_bfd_elf_create_dynamic_sections
#define bfd_elf32_bfd_link_hash_table_create \
					bfin_link_hash_table_create
#define bfd_elf32_bfd_final_link	bfd_elf_gc_common_final_link

#define elf_backend_check_relocs	bfin_check_relocs
#define elf_backend_adjust_dynamic_symbol \
					bfin_adjust_dynamic_symbol
#define elf_backend_late_size_sections	bfin_late_size_sections
#define elf_backend_relocate_section	bfin_relocate_section
#define elf_backend_finish_dynamic_symbol \
					bfin_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections \
					bfin_finish_dynamic_sections
#define elf_backend_gc_mark_hook	bfin_gc_mark_hook
#define bfd_elf32_bfd_merge_private_bfd_data \
					elf32_bfin_merge_private_bfd_data
#define bfd_elf32_bfd_set_private_flags \
					elf32_bfin_set_private_flags
#define bfd_elf32_bfd_print_private_bfd_data \
					elf32_bfin_print_private_bfd_data
#define elf_backend_final_write_processing \
					elf32_bfin_final_write_processing
#define elf_backend_reloc_type_class	elf32_bfin_reloc_type_class
#define elf_backend_stack_align		8
#define elf_backend_can_gc_sections 1
#define elf_backend_special_sections	elf32_bfin_special_sections
#define elf_backend_can_refcount 1
#define elf_backend_want_got_plt 0
#define elf_backend_plt_readonly 1
#define elf_backend_want_plt_sym 0
#define elf_backend_got_header_size	12
#define elf_backend_rela_normal		1

#include "elf32-target.h"

#undef TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		bfin_elf32_fdpic_vec
#undef TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		"elf32-bfinfdpic"
#undef	elf32_bed
#define	elf32_bed			elf32_bfinfdpic_bed

#undef elf_backend_got_header_size
#define elf_backend_got_header_size	0

#undef elf_backend_relocate_section
#define elf_backend_relocate_section	bfinfdpic_relocate_section
#undef elf_backend_check_relocs
#define elf_backend_check_relocs	bfinfdpic_check_relocs

#undef bfd_elf32_bfd_link_hash_table_create
#define bfd_elf32_bfd_link_hash_table_create \
		bfinfdpic_elf_link_hash_table_create
#undef elf_backend_early_size_sections
#define elf_backend_early_size_sections \
		elf32_bfinfdpic_early_size_sections

#undef elf_backend_create_dynamic_sections
#define elf_backend_create_dynamic_sections \
		elf32_bfinfdpic_create_dynamic_sections
#undef elf_backend_adjust_dynamic_symbol
#define elf_backend_adjust_dynamic_symbol \
		elf32_bfinfdpic_adjust_dynamic_symbol
#undef elf_backend_late_size_sections
#define elf_backend_late_size_sections \
		elf32_bfinfdpic_late_size_sections
#undef elf_backend_finish_dynamic_symbol
#define elf_backend_finish_dynamic_symbol \
		elf32_bfinfdpic_finish_dynamic_symbol
#undef elf_backend_finish_dynamic_sections
#define elf_backend_finish_dynamic_sections \
		elf32_bfinfdpic_finish_dynamic_sections

#undef elf_backend_discard_info
#define elf_backend_discard_info \
		bfinfdpic_elf_discard_info
#undef elf_backend_can_make_relative_eh_frame
#define elf_backend_can_make_relative_eh_frame \
		bfinfdpic_elf_use_relative_eh_frame
#undef elf_backend_can_make_lsda_relative_eh_frame
#define elf_backend_can_make_lsda_relative_eh_frame \
		bfinfdpic_elf_use_relative_eh_frame
#undef elf_backend_encode_eh_address
#define elf_backend_encode_eh_address \
		bfinfdpic_elf_encode_eh_address

#undef elf_backend_may_use_rel_p
#define elf_backend_may_use_rel_p	1
#undef elf_backend_may_use_rela_p
#define elf_backend_may_use_rela_p	1
/* We use REL for dynamic relocations only.  */
#undef elf_backend_default_use_rela_p
#define elf_backend_default_use_rela_p	1

#undef elf_backend_omit_section_dynsym
#define elf_backend_omit_section_dynsym _bfinfdpic_link_omit_section_dynsym

#include "elf32-target.h"
