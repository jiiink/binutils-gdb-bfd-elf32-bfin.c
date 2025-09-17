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


static bool is_undefined_symbol(asymbol *symbol, bool relocatable)
{
    return bfd_is_und_section(symbol->section) 
           && (symbol->flags & BSF_WEAK) == 0 
           && !relocatable;
}

static bfd_vma calculate_initial_relocation(asymbol *symbol)
{
    if (bfd_is_com_section(symbol->section))
        return 0;
    return symbol->value;
}

static bfd_vma get_output_base(asymbol *symbol, bool relocatable)
{
    if (relocatable)
        return 0;
    return symbol->section->output_section->vma;
}

static bool should_add_output_offset(asymbol *symbol, bool relocatable)
{
    return !relocatable || !strcmp(symbol->name, symbol->section->name);
}

static bool should_add_addend(asymbol *symbol, bool relocatable, arelent *reloc_entry)
{
    return !relocatable && !strcmp(symbol->name, symbol->section->name);
}

static bfd_vma calculate_relative_address(bfd_vma relocation, 
                                          asection *input_section,
                                          bfd_size_type addr)
{
    relocation -= input_section->output_section->vma + input_section->output_offset;
    relocation -= addr;
    return relocation;
}

static bfd_reloc_status_type check_overflow_if_needed(reloc_howto_type *howto,
                                                      bfd_vma relocation,
                                                      bfd *abfd)
{
    if (howto->complain_on_overflow == complain_overflow_dont)
        return bfd_reloc_ok;
    
    return bfd_check_overflow(howto->complain_on_overflow,
                             howto->bitsize,
                             howto->rightshift,
                             bfd_arch_bits_per_address(abfd),
                             relocation);
}

static bfd_reloc_status_type validate_even_relocation(reloc_howto_type *howto,
                                                      bfd_vma relocation)
{
    #define ODD_BIT_MASK 0x01
    
    if (howto->rightshift && (relocation & ODD_BIT_MASK))
    {
        _bfd_error_handler(_("relocation should be even number"));
        return bfd_reloc_overflow;
    }
    return bfd_reloc_ok;
}

static void update_relocatable_addresses(arelent *reloc_entry,
                                         asection *input_section,
                                         asymbol *symbol)
{
    reloc_entry->address += input_section->output_offset;
    reloc_entry->addend += symbol->section->output_offset;
}

static void write_relocation_data(bfd *abfd, void *data, bfd_size_type addr, 
                                  bfd_vma relocation)
{
    #define INSTRUCTION_OFFSET 2
    #define HIGH_BYTE_MASK 0xff00
    #define LOW_WORD_MASK 0xFFFF
    #define HIGH_BYTE_SHIFT 16
    #define RELOCATION_ADJUSTMENT 1
    
    short x;
    bfd_byte *data_ptr = (bfd_byte *)data;
    
    relocation += RELOCATION_ADJUSTMENT;
    
    x = bfd_get_16(abfd, data_ptr + addr - INSTRUCTION_OFFSET);
    x = (x & HIGH_BYTE_MASK) | ((relocation >> HIGH_BYTE_SHIFT) & 0xff);
    bfd_put_16(abfd, x, data_ptr + addr - INSTRUCTION_OFFSET);
    
    x = relocation & LOW_WORD_MASK;
    bfd_put_16(abfd, x, data_ptr + addr);
}

static bfd_reloc_status_type
bfin_pcrel24_reloc(bfd *abfd,
                   arelent *reloc_entry,
                   asymbol *symbol,
                   void *data,
                   asection *input_section,
                   bfd *output_bfd,
                   char **error_message ATTRIBUTE_UNUSED)
{
    #define INSTRUCTION_OFFSET 2
    
    bfd_size_type addr = reloc_entry->address;
    reloc_howto_type *howto = reloc_entry->howto;
    bool relocatable = (output_bfd != NULL);
    bfd_reloc_status_type status;
    bfd_vma relocation;
    bfd_vma output_base;
    
    if (!bfd_reloc_offset_in_range(howto, abfd, input_section, addr - INSTRUCTION_OFFSET))
        return bfd_reloc_outofrange;
    
    if (is_undefined_symbol(symbol, relocatable))
        return bfd_reloc_undefined;
    
    relocation = calculate_initial_relocation(symbol);
    output_base = get_output_base(symbol, relocatable);
    
    if (should_add_output_offset(symbol, relocatable))
        relocation += output_base + symbol->section->output_offset;
    
    if (should_add_addend(symbol, relocatable, reloc_entry))
        relocation += reloc_entry->addend;
    
    relocation = calculate_relative_address(relocation, input_section, addr);
    
    status = check_overflow_if_needed(howto, relocation, abfd);
    if (status != bfd_reloc_ok)
        return status;
    
    status = validate_even_relocation(howto, relocation);
    if (status != bfd_reloc_ok)
        return status;
    
    relocation >>= (bfd_vma)howto->rightshift;
    relocation <<= (bfd_vma)howto->bitpos;
    
    if (relocatable)
        update_relocatable_addresses(reloc_entry, input_section, symbol);
    
    write_relocation_data(abfd, data, addr, relocation);
    
    return bfd_reloc_ok;
}

static bool is_relocation_in_range(reloc_howto_type *howto, bfd *abfd, 
                                   asection *input_section, bfd_size_type reloc_addr)
{
    return bfd_reloc_offset_in_range(howto, abfd, input_section, reloc_addr);
}

static bool is_undefined_non_weak_symbol(asymbol *symbol, bool relocatable)
{
    return bfd_is_und_section(symbol->section) 
           && (symbol->flags & BSF_WEAK) == 0 
           && !relocatable;
}

static bfd_vma calculate_output_base(asymbol *symbol, bool relocatable)
{
    if (relocatable)
        return 0;
    return symbol->section->output_section->vma;
}

static bfd_vma calculate_relocation(asymbol *symbol, bfd_vma output_base, 
                                    bool relocatable, arelent *reloc_entry)
{
    bfd_vma relocation = symbol->value;
    
    if (!relocatable || !strcmp(symbol->name, symbol->section->name))
        relocation += output_base + symbol->section->output_offset;
    
    relocation += reloc_entry->addend;
    return relocation;
}

static void update_reloc_entry_for_relocatable(arelent *reloc_entry, 
                                               asection *input_section, 
                                               asymbol *symbol)
{
    reloc_entry->address += input_section->output_offset;
    reloc_entry->addend += symbol->section->output_offset;
}

static bfd_reloc_status_type check_relocation_overflow(reloc_howto_type *howto, 
                                                       bfd *abfd, 
                                                       bfd_vma relocation)
{
    if (howto->complain_on_overflow == complain_overflow_dont)
        return bfd_reloc_ok;
    
    return bfd_check_overflow(howto->complain_on_overflow,
                             howto->bitsize,
                             howto->rightshift,
                             bfd_arch_bits_per_address(abfd),
                             relocation);
}

static void apply_relocation(bfd *abfd, bfd_vma relocation, 
                            reloc_howto_type *howto, void *data, 
                            bfd_size_type reloc_addr)
{
    relocation >>= (bfd_vma) howto->rightshift;
    bfd_put_16(abfd, relocation, (unsigned char *) data + reloc_addr);
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
    bfd_size_type reloc_addr = reloc_entry->address;
    reloc_howto_type *howto = reloc_entry->howto;
    bool relocatable = (output_bfd != NULL);
    
    if (!is_relocation_in_range(howto, abfd, input_section, reloc_addr))
        return bfd_reloc_outofrange;
    
    if (is_undefined_non_weak_symbol(symbol, relocatable))
        return bfd_reloc_undefined;
    
    bfd_vma output_base = calculate_output_base(symbol, relocatable);
    bfd_vma relocation = calculate_relocation(symbol, output_base, relocatable, reloc_entry);
    
    if (relocatable)
        update_reloc_entry_for_relocatable(reloc_entry, input_section, symbol);
    else
        reloc_entry->addend = 0;
    
    bfd_reloc_status_type overflow_status = check_relocation_overflow(howto, abfd, relocation);
    if (overflow_status != bfd_reloc_ok)
        return overflow_status;
    
    apply_relocation(abfd, relocation, howto, data, reloc_addr);
    return bfd_reloc_ok;
}


static bool is_valid_relocation_address(arelent *reloc_entry, bfd *abfd, asection *input_section)
{
    return bfd_reloc_offset_in_range(reloc_entry->howto, abfd, input_section, reloc_entry->address);
}

static bool is_undefined_symbol(asymbol *symbol, bool relocatable)
{
    return bfd_is_und_section(symbol->section) 
           && (symbol->flags & BSF_WEAK) == 0 
           && !relocatable;
}

static bool should_add_output_offset(asymbol *symbol, bool relocatable)
{
    return (symbol->name 
            && symbol->section->name 
            && !strcmp(symbol->name, symbol->section->name))
           || !relocatable;
}

static bfd_vma calculate_relocation(asymbol *symbol, arelent *reloc_entry, bool relocatable)
{
    bfd_vma relocation = symbol->value;
    bfd_vma output_base = relocatable ? 0 : symbol->section->output_section->vma;
    
    if (should_add_output_offset(symbol, relocatable))
    {
        relocation += output_base + symbol->section->output_offset;
    }
    
    relocation += reloc_entry->addend;
    return relocation;
}

static void update_reloc_entry(arelent *reloc_entry, asection *input_section, asymbol *symbol, bool relocatable)
{
    if (relocatable)
    {
        reloc_entry->address += input_section->output_offset;
        reloc_entry->addend += symbol->section->output_offset;
    }
    else
    {
        reloc_entry->addend = 0;
    }
}

#define UPPER_WORD_MASK 0xFFFF0000
#define LOWER_WORD_MASK 0x0000FFFF
#define WORD_SHIFT 16
#define UPPER_WORD_OFFSET 2

static void write_relocation_data(bfd *abfd, bfd_vma relocation, void *data, bfd_size_type addr)
{
    bfd_vma upper_word = (relocation & UPPER_WORD_MASK) >> WORD_SHIFT;
    bfd_vma lower_word = relocation & LOWER_WORD_MASK;
    
    bfd_put_16(abfd, upper_word, (unsigned char *)data + addr + UPPER_WORD_OFFSET);
    bfd_put_16(abfd, lower_word, (unsigned char *)data + addr);
}

static bfd_reloc_status_type
bfin_byte4_reloc(bfd *abfd,
                 arelent *reloc_entry,
                 asymbol *symbol,
                 void *data,
                 asection *input_section,
                 bfd *output_bfd,
                 char **error_message ATTRIBUTE_UNUSED)
{
    bool relocatable = (output_bfd != NULL);
    
    if (!is_valid_relocation_address(reloc_entry, abfd, input_section))
        return bfd_reloc_outofrange;
    
    if (is_undefined_symbol(symbol, relocatable))
        return bfd_reloc_undefined;
    
    bfd_vma relocation = calculate_relocation(symbol, reloc_entry, relocatable);
    update_reloc_entry(reloc_entry, input_section, symbol, relocatable);
    write_relocation_data(abfd, relocation, data, reloc_entry->address);
    
    return bfd_reloc_ok;
}

/* bfin_bfd_reloc handles the blackfin arithmetic relocations.
   Use this instead of bfd_perform_relocation.  */
static bool is_undefined_symbol(asymbol *symbol, bool relocatable)
{
  return bfd_is_und_section(symbol->section) 
         && (symbol->flags & BSF_WEAK) == 0 
         && !relocatable;
}

static bfd_vma get_symbol_value(asymbol *symbol)
{
  if (bfd_is_com_section(symbol->section))
    return 0;
  return symbol->value;
}

static bfd_vma calculate_output_base(asymbol *symbol, bool relocatable)
{
  if (relocatable)
    return 0;
  return symbol->section->output_section->vma;
}

static bool should_add_output_offset(asymbol *symbol, bool relocatable)
{
  return !relocatable || !strcmp(symbol->name, symbol->section->name);
}

static bfd_vma apply_pc_relative_adjustment(bfd_vma relocation, 
                                           reloc_howto_type *howto,
                                           asection *input_section,
                                           bfd_size_type addr)
{
  if (!howto->pc_relative)
    return relocation;
    
  relocation -= input_section->output_section->vma + input_section->output_offset;
  
  if (howto->pcrel_offset)
    relocation -= addr;
    
  return relocation;
}

static void update_relocatable_fields(arelent *reloc_entry,
                                     asection *input_section,
                                     asymbol *symbol)
{
  reloc_entry->address += input_section->output_offset;
  reloc_entry->addend += symbol->section->output_offset;
}

static bfd_reloc_status_type check_relocation_overflow(reloc_howto_type *howto,
                                                      bfd_vma relocation,
                                                      bfd *abfd)
{
  if (howto->complain_on_overflow == complain_overflow_dont)
    return bfd_reloc_ok;
    
  return bfd_check_overflow(howto->complain_on_overflow,
                           howto->bitsize,
                           howto->rightshift,
                           bfd_arch_bits_per_address(abfd),
                           relocation);
}

#define ODD_RELOCATION_MASK 0x01

static bfd_reloc_status_type check_even_relocation(reloc_howto_type *howto,
                                                  bfd_vma relocation)
{
  if (howto->rightshift && (relocation & ODD_RELOCATION_MASK))
    {
      _bfd_error_handler(_("relocation should be even number"));
      return bfd_reloc_overflow;
    }
  return bfd_reloc_ok;
}

static bfd_vma prepare_relocation_value(bfd_vma relocation,
                                       reloc_howto_type *howto)
{
  relocation >>= (bfd_vma) howto->rightshift;
  relocation <<= (bfd_vma) howto->bitpos;
  return relocation;
}

#define APPLY_MASK(x, howto, relocation) \
  ((x & ~howto->dst_mask) | (relocation & howto->dst_mask))

static bfd_reloc_status_type apply_8bit_relocation(bfd *abfd,
                                                  void *data,
                                                  bfd_size_type addr,
                                                  reloc_howto_type *howto,
                                                  bfd_vma relocation)
{
  char x = bfd_get_8(abfd, (char *) data + addr);
  x = APPLY_MASK(x, howto, relocation);
  bfd_put_8(abfd, x, (unsigned char *) data + addr);
  return bfd_reloc_ok;
}

static bfd_reloc_status_type apply_16bit_relocation(bfd *abfd,
                                                   void *data,
                                                   bfd_size_type addr,
                                                   reloc_howto_type *howto,
                                                   bfd_vma relocation)
{
  unsigned short x = bfd_get_16(abfd, (bfd_byte *) data + addr);
  x = APPLY_MASK(x, howto, relocation);
  bfd_put_16(abfd, (bfd_vma) x, (unsigned char *) data + addr);
  return bfd_reloc_ok;
}

static bfd_reloc_status_type apply_relocation(bfd *abfd,
                                             void *data,
                                             bfd_size_type addr,
                                             reloc_howto_type *howto,
                                             bfd_vma relocation)
{
  switch (bfd_get_reloc_size(howto))
    {
    case 1:
      return apply_8bit_relocation(abfd, data, addr, howto, relocation);
    case 2:
      return apply_16bit_relocation(abfd, data, addr, howto, relocation);
    default:
      return bfd_reloc_other;
    }
}

static bfd_reloc_status_type
bfin_bfd_reloc(bfd *abfd,
               arelent *reloc_entry,
               asymbol *symbol,
               void *data,
               asection *input_section,
               bfd *output_bfd,
               char **error_message ATTRIBUTE_UNUSED)
{
  bfd_size_type addr = reloc_entry->address;
  reloc_howto_type *howto = reloc_entry->howto;
  bool relocatable = (output_bfd != NULL);
  bfd_reloc_status_type status;

  if (!bfd_reloc_offset_in_range(howto, abfd, input_section, addr))
    return bfd_reloc_outofrange;

  if (is_undefined_symbol(symbol, relocatable))
    return bfd_reloc_undefined;

  bfd_vma relocation = get_symbol_value(symbol);
  bfd_vma output_base = calculate_output_base(symbol, relocatable);

  if (should_add_output_offset(symbol, relocatable))
    relocation += output_base + symbol->section->output_offset;

  if (!relocatable && !strcmp(symbol->name, symbol->section->name))
    relocation += reloc_entry->addend;

  relocation = apply_pc_relative_adjustment(relocation, howto, input_section, addr);

  if (relocatable)
    update_relocatable_fields(reloc_entry, input_section, symbol);

  status = check_relocation_overflow(howto, relocation, abfd);
  if (status != bfd_reloc_ok)
    return status;

  status = check_even_relocation(howto, relocation);
  if (status != bfd_reloc_ok)
    return status;

  relocation = prepare_relocation_value(relocation, howto);

  return apply_relocation(abfd, data, addr, howto, relocation);
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
bfin_info_to_howto (bfd *abfd,
		    arelent *cache_ptr,
		    Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (dst->r_info);

  if (r_type <= BFIN_RELOC_MAX)
    {
      cache_ptr->howto = &bfin_howto_table [r_type];
      return true;
    }

  if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
    {
      cache_ptr->howto = &bfin_gnuext_howto_table [r_type - BFIN_GNUEXT_RELOC_MIN];
      return true;
    }

  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
		      abfd, r_type);
  bfd_set_error (bfd_error_bad_value);
  return false;
}

/* Given a BFD reloc type, return the howto.  */
static reloc_howto_type *
bfin_bfd_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
			    bfd_reloc_code_real_type code)
{
  unsigned int r_type = (unsigned int) -1;
  size_t map_size = sizeof (bfin_reloc_map) / sizeof (bfin_reloc_map[0]);

  for (size_t i = 0; i < map_size; i++)
    if (bfin_reloc_map[i].bfd_reloc_val == code)
    {
      r_type = bfin_reloc_map[i].bfin_reloc_val;
      break;
    }

  if (r_type <= BFIN_RELOC_MAX)
    return &bfin_howto_table [r_type];

  if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
    return &bfin_gnuext_howto_table [r_type - BFIN_GNUEXT_RELOC_MIN];

  return (reloc_howto_type *) NULL;
}

static reloc_howto_type *
search_howto_table(const reloc_howto_type *table, size_t table_size, const char *r_name)
{
  unsigned int i;
  
  for (i = 0; i < table_size; i++)
    if (table[i].name != NULL && strcasecmp(table[i].name, r_name) == 0)
      return (reloc_howto_type *)&table[i];
  
  return NULL;
}

static reloc_howto_type *
bfin_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{
  reloc_howto_type *result;
  
  result = search_howto_table(bfin_howto_table, 
                              sizeof(bfin_howto_table) / sizeof(bfin_howto_table[0]),
                              r_name);
  if (result != NULL)
    return result;
  
  return search_howto_table(bfin_gnuext_howto_table,
                           sizeof(bfin_gnuext_howto_table) / sizeof(bfin_gnuext_howto_table[0]),
                           r_name);
}

/* Given a bfin relocation type, return the howto.  */
static reloc_howto_type *
bfin_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
			unsigned int r_type)
{
  if (r_type <= BFIN_RELOC_MAX)
    return &bfin_howto_table[r_type];

  if (r_type >= BFIN_GNUEXT_RELOC_MIN && r_type <= BFIN_GNUEXT_RELOC_MAX)
    return &bfin_gnuext_howto_table[r_type - BFIN_GNUEXT_RELOC_MIN];

  return NULL;
}

/* Set by ld emulation if --code-in-l1.  */
bool elf32_bfin_code_in_l1 = 0;

/* Set by ld emulation if --data-in-l1.  */
bool elf32_bfin_data_in_l1 = 0;

static bool
elf32_bfin_final_write_processing (bfd *abfd)
{
  if (elf32_bfin_code_in_l1)
    elf_elfheader (abfd)->e_flags |= EF_BFIN_CODE_IN_L1;
  if (elf32_bfin_data_in_l1)
    elf_elfheader (abfd)->e_flags |= EF_BFIN_DATA_IN_L1;
  return _bfd_elf_final_write_processing (abfd);
}

/* Return TRUE if the name is a local label.
   bfin local labels begin with L$.  */
static bool
bfin_is_local_label_name (bfd *abfd, const char *label)
{
  const char LOCAL_LABEL_PREFIX = 'L';
  const char LOCAL_LABEL_SUFFIX = '$';
  
  if (label[0] == LOCAL_LABEL_PREFIX && label[1] == LOCAL_LABEL_SUFFIX)
    return true;

  return _bfd_elf_is_local_label_name (abfd, label);
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bool
initialize_got_sections(bfd *abfd, struct bfd_link_info *info, asection **sgot, asection **srelgot)
{
    bfd *dynobj = elf_hash_table(info)->dynobj;
    
    if (dynobj == NULL)
    {
        elf_hash_table(info)->dynobj = abfd;
        if (!_bfd_elf_create_got_section(abfd, info))
            return false;
    }
    
    *sgot = elf_hash_table(info)->sgot;
    *srelgot = elf_hash_table(info)->srelgot;
    BFD_ASSERT(*sgot != NULL);
    
    return true;
}

static struct elf_link_hash_entry *
resolve_hash_entry(struct elf_link_hash_entry *h)
{
    while (h->root.type == bfd_link_hash_indirect || 
           h->root.type == bfd_link_hash_warning)
    {
        h = (struct elf_link_hash_entry *)h->root.u.i.link;
    }
    return h;
}

static bool
handle_global_got_entry(struct elf_link_hash_entry *h, struct bfd_link_info *info,
                       asection *sgot, asection *srelgot)
{
    if (h->got.refcount == 0)
    {
        if (h->dynindx == -1 && !h->forced_local)
        {
            if (!bfd_elf_link_record_dynamic_symbol(info, h))
                return false;
        }
        
        sgot->size += 4;
        srelgot->size += sizeof(Elf32_External_Rela);
    }
    h->got.refcount++;
    return true;
}

static bool
handle_local_got_entry(bfd *abfd, unsigned long r_symndx, struct bfd_link_info *info,
                      asection *sgot, asection *srelgot, bfd_signed_vma **local_got_refcounts)
{
    if (*local_got_refcounts == NULL)
    {
        Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
        bfd_size_type size = symtab_hdr->sh_info * sizeof(bfd_signed_vma);
        
        *local_got_refcounts = (bfd_signed_vma *)bfd_zalloc(abfd, size);
        if (*local_got_refcounts == NULL)
            return false;
        elf_local_got_refcounts(abfd) = *local_got_refcounts;
    }
    
    if ((*local_got_refcounts)[r_symndx] == 0)
    {
        sgot->size += 4;
        if (bfd_link_pic(info))
            srelgot->size += sizeof(Elf32_External_Rela);
    }
    (*local_got_refcounts)[r_symndx]++;
    return true;
}

static bool
process_got_relocation(bfd *abfd, struct bfd_link_info *info, 
                      struct elf_link_hash_entry *h, unsigned long r_symndx,
                      asection **sgot, asection **srelgot, bfd_signed_vma **local_got_refcounts)
{
    if (h != NULL && strcmp(h->root.root.string, "__GLOBAL_OFFSET_TABLE_") == 0)
        return true;
    
    if (*sgot == NULL)
    {
        if (!initialize_got_sections(abfd, info, sgot, srelgot))
            return false;
    }
    
    if (h != NULL)
        return handle_global_got_entry(h, info, *sgot, *srelgot);
    else
        return handle_local_got_entry(abfd, r_symndx, info, *sgot, *srelgot, local_got_refcounts);
}

static bool
bfin_check_relocs(bfd *abfd, struct bfd_link_info *info,
                 asection *sec, const Elf_Internal_Rela *relocs)
{
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    bfd_signed_vma *local_got_refcounts;
    const Elf_Internal_Rela *rel;
    const Elf_Internal_Rela *rel_end;
    asection *sgot = NULL;
    asection *srelgot = NULL;
    
    if (bfd_link_relocatable(info))
        return true;
    
    symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    sym_hashes = elf_sym_hashes(abfd);
    local_got_refcounts = elf_local_got_refcounts(abfd);
    
    rel_end = relocs + sec->reloc_count;
    for (rel = relocs; rel < rel_end; rel++)
    {
        unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
        struct elf_link_hash_entry *h = NULL;
        
        if (r_symndx >= symtab_hdr->sh_info)
        {
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];
            h = resolve_hash_entry(h);
        }
        
        switch (ELF32_R_TYPE(rel->r_info))
        {
        case R_BFIN_GNU_VTINHERIT:
            if (!bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset))
                return false;
            break;
            
        case R_BFIN_GNU_VTENTRY:
            if (!bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend))
                return false;
            break;
            
        case R_BFIN_GOT:
            if (!process_got_relocation(abfd, info, h, r_symndx, &sgot, &srelgot, &local_got_refcounts))
                return false;
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
			     const Elf_Internal_Rela * rela)
{
  return reloc_class_normal;
}

static bfd_reloc_status_type
check_pcrel24_overflow(bfd_vma value)
{
  if ((value & 0xFF000000) != 0 && (value & 0xFF000000) != 0xFF000000)
    return bfd_reloc_overflow;
  return bfd_reloc_ok;
}

static bfd_vma
calculate_pcrel_value(bfd_vma value, bfd_vma addend, asection *input_section, bfd_vma address)
{
  value += addend;
  value -= input_section->output_section->vma + input_section->output_offset;
  value -= address;
  return value;
}

static void
write_pcrel24_value(bfd *input_bfd, bfd_byte *contents, bfd_vma address, bfd_vma value)
{
  bfd_vma x;
  
  value >>= 1;
  
  x = bfd_get_16(input_bfd, contents + address);
  x = (x & 0xff00) | ((value >> 16) & 0xff);
  bfd_put_16(input_bfd, x, contents + address);
  
  x = value & 0xFFFF;
  bfd_put_16(input_bfd, x, contents + address + 2);
}

static bfd_reloc_status_type
handle_pcrel24_relocation(Elf_Internal_Rela *rel, reloc_howto_type *howto,
                          bfd *input_bfd, asection *input_section,
                          bfd_byte *contents, bfd_vma address,
                          bfd_vma value, bfd_vma addend)
{
  #define PCREL_OFFSET_ADJUSTMENT 2
  
  if (!bfd_reloc_offset_in_range(howto, input_bfd, input_section,
                                 address - PCREL_OFFSET_ADJUSTMENT))
    return bfd_reloc_outofrange;
  
  value = calculate_pcrel_value(value, addend, input_section, address);
  value += PCREL_OFFSET_ADJUSTMENT;
  address -= PCREL_OFFSET_ADJUSTMENT;
  
  bfd_reloc_status_type status = check_pcrel24_overflow(value);
  
  write_pcrel24_value(input_bfd, contents, address, value);
  
  return status;
}

static bfd_reloc_status_type
bfin_final_link_relocate(Elf_Internal_Rela *rel, reloc_howto_type *howto,
                        bfd *input_bfd, asection *input_section,
                        bfd_byte *contents, bfd_vma address,
                        bfd_vma value, bfd_vma addend)
{
  int r_type = ELF32_R_TYPE(rel->r_info);
  
  if (r_type == R_BFIN_PCREL24 || r_type == R_BFIN_PCREL24_JUMP_L)
    return handle_pcrel24_relocation(rel, howto, input_bfd, input_section,
                                     contents, address, value, addend);
  
  return _bfd_final_link_relocate(howto, input_bfd, input_section, contents,
                                  rel->r_offset, value, addend);
}

static bool
validate_relocation_type(int r_type)
{
    if (r_type < 0 || r_type >= 243)
    {
        bfd_set_error(bfd_error_bad_value);
        return false;
    }
    return true;
}

static bool
skip_vtable_relocation(int r_type)
{
    return r_type == R_BFIN_GNU_VTENTRY || r_type == R_BFIN_GNU_VTINHERIT;
}

static bool
get_relocation_howto(bfd *input_bfd, int r_type, reloc_howto_type **howto)
{
    *howto = bfin_reloc_type_lookup(input_bfd, r_type);
    if (*howto == NULL)
    {
        bfd_set_error(bfd_error_bad_value);
        return false;
    }
    return true;
}

static void
resolve_local_symbol(Elf_Internal_Sym *local_syms, asection **local_sections,
                    unsigned long r_symndx, bfd *output_bfd,
                    Elf_Internal_Rela *rel, Elf_Internal_Sym **sym,
                    asection **sec, bfd_vma *relocation)
{
    *sym = local_syms + r_symndx;
    *sec = local_sections[r_symndx];
    *relocation = _bfd_elf_rela_local_sym(output_bfd, *sym, sec, rel);
}

static void
resolve_global_symbol(struct bfd_link_info *info, bfd *input_bfd,
                     asection *input_section, Elf_Internal_Rela *rel,
                     unsigned long r_symndx, Elf_Internal_Shdr *symtab_hdr,
                     struct elf_link_hash_entry **sym_hashes,
                     struct elf_link_hash_entry **h, asection **sec,
                     bfd_vma *relocation, bool *unresolved_reloc)
{
    bool warned, ignored;
    RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                           r_symndx, symtab_hdr, sym_hashes,
                           *h, *sec, *relocation,
                           *unresolved_reloc, warned, ignored);
}

static bool
ensure_got_section_exists(bfd **dynobj, bfd *output_bfd, struct bfd_link_info *info)
{
    if (*dynobj == NULL)
    {
        elf_hash_table(info)->dynobj = *dynobj = output_bfd;
        if (!_bfd_elf_create_got_section(*dynobj, info))
            return false;
    }
    return true;
}

static bool
needs_static_initialization(struct bfd_link_info *info,
                           struct elf_link_hash_entry *h)
{
    bool dyn = elf_hash_table(info)->dynamic_sections_created;
    return !WILL_CALL_FINISH_DYNAMIC_SYMBOL(dyn, bfd_link_pic(info), h) ||
           (bfd_link_pic(info) &&
            (info->symbolic || h->dynindx == -1 || h->forced_local) &&
            h->def_regular);
}

static void
initialize_got_entry(bfd *output_bfd, asection *sgot, bfd_vma off,
                    bfd_vma relocation, struct elf_link_hash_entry *h)
{
    bfd_put_32(output_bfd, relocation, sgot->contents + off);
    if (h)
        h->got.offset |= 1;
}

static void
create_dynamic_got_relocation(bfd *output_bfd, struct bfd_link_info *info,
                             asection *sgot, bfd_vma off, bfd_vma relocation)
{
    asection *s;
    Elf_Internal_Rela outrel;
    bfd_byte *loc;

    s = elf_hash_table(info)->srelgot;
    BFD_ASSERT(s != NULL);

    outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off;
    outrel.r_info = ELF32_R_INFO(0, R_BFIN_PCREL24);
    outrel.r_addend = relocation;
    loc = s->contents;
    loc += s->reloc_count++ * sizeof(Elf32_External_Rela);
    bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
}

static bfd_vma
process_got_entry_for_hash(bfd *output_bfd, struct bfd_link_info *info,
                           struct elf_link_hash_entry *h, asection *sgot,
                           bfd_vma relocation, bool *unresolved_reloc)
{
    bfd_vma off = h->got.offset;
    BFD_ASSERT(off != (bfd_vma)-1);

    if (needs_static_initialization(info, h))
    {
        if ((off & 1) != 0)
            off &= ~1;
        else
        {
            initialize_got_entry(output_bfd, sgot, off, relocation, h);
        }
    }
    else
        *unresolved_reloc = false;

    return off;
}

static bfd_vma
process_got_entry_for_local(bfd *output_bfd, struct bfd_link_info *info,
                           unsigned long r_symndx, bfd_vma *local_got_offsets,
                           asection *sgot, bfd_vma relocation)
{
    BFD_ASSERT(local_got_offsets != NULL);
    bfd_vma off = local_got_offsets[r_symndx];
    BFD_ASSERT(off != (bfd_vma)-1);

    if ((off & 1) != 0)
        off &= ~1;
    else
    {
        bfd_put_32(output_bfd, relocation, sgot->contents + off);

        if (bfd_link_pic(info))
        {
            create_dynamic_got_relocation(output_bfd, info, sgot, off, relocation);
        }

        local_got_offsets[r_symndx] |= 1;
    }

    return off;
}

static bfd_vma
process_got_relocation(bfd **dynobj, bfd *output_bfd, struct bfd_link_info *info,
                      struct elf_link_hash_entry *h, unsigned long r_symndx,
                      bfd_vma *local_got_offsets, bfd_vma relocation,
                      bool *unresolved_reloc)
{
    bfd_vma off;
    asection *sgot;

    if (!ensure_got_section_exists(dynobj, output_bfd, info))
        return (bfd_vma)-1;

    sgot = elf_hash_table(info)->sgot;
    BFD_ASSERT(sgot != NULL);

    if (h != NULL)
    {
        off = process_got_entry_for_hash(output_bfd, info, h, sgot,
                                         relocation, unresolved_reloc);
    }
    else
    {
        off = process_got_entry_for_local(output_bfd, info, r_symndx,
                                         local_got_offsets, sgot, relocation);
    }

    return sgot->output_offset + off;
}

static const char *
get_symbol_name(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr,
               struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
               asection *sec)
{
    const char *name;

    if (h != NULL)
        return h->root.root.string;

    name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link,
                                           sym->st_name);
    if (name == NULL)
        return NULL;
    if (*name == '\0')
        name = bfd_section_name(sec);

    return name;
}

static bool
handle_relocation_error(struct bfd_link_info *info, bfd *input_bfd,
                       asection *input_section, Elf_Internal_Rela *rel,
                       struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                       Elf_Internal_Shdr *symtab_hdr, asection *sec,
                       reloc_howto_type *howto, bfd_reloc_status_type r)
{
    const char *name = get_symbol_name(input_bfd, symtab_hdr, h, sym, sec);
    if (name == NULL)
        return false;

    if (r == bfd_reloc_overflow)
    {
        (*info->callbacks->reloc_overflow)
            (info, (h ? &h->root : NULL), name, howto->name,
             (bfd_vma)0, input_bfd, input_section, rel->r_offset);
    }
    else
    {
        _bfd_error_handler
            (_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
             input_bfd, input_section, (uint64_t)rel->r_offset,
             name, (int)r);
        return false;
    }
    return true;
}

static bool
handle_unresolved_relocation(struct bfd_link_info *info, bfd *input_bfd,
                            asection *input_section, Elf_Internal_Rela *rel,
                            struct elf_link_hash_entry *h, bool unresolved_reloc)
{
    if (unresolved_reloc &&
        !((input_section->flags & SEC_DEBUGGING) != 0 && h->def_dynamic) &&
        _bfd_elf_section_offset(output_bfd, info, input_section,
                               rel->r_offset) != (bfd_vma)-1)
    {
        _bfd_error_handler
            (_("%pB(%pA+%#" PRIx64 "): "
               "unresolvable relocation against symbol `%s'"),
             input_bfd, input_section, (uint64_t)rel->r_offset,
             h->root.root.string);
        return false;
    }
    return true;
}

static bool
process_single_relocation(bfd *output_bfd, struct bfd_link_info *info,
                         bfd *input_bfd, asection *input_section,
                         bfd_byte *contents, Elf_Internal_Rela *rel,
                         Elf_Internal_Rela *relend, Elf_Internal_Sym *local_syms,
                         asection **local_sections, Elf_Internal_Shdr *symtab_hdr,
                         struct elf_link_hash_entry **sym_hashes,
                         bfd_vma *local_got_offsets, bfd **dynobj)
{
    int r_type;
    reloc_howto_type *howto;
    unsigned long r_symndx;
    struct elf_link_hash_entry *h = NULL;
    Elf_Internal_Sym *sym = NULL;
    asection *sec = NULL;
    bfd_vma relocation = 0;
    bool unresolved_reloc = false;
    bfd_reloc_status_type r;
    bfd_vma address;

    r_type = ELF32_R_TYPE(rel->r_info);
    
    if (!validate_relocation_type(r_type))
        return false;

    if (skip_vtable_relocation(r_type))
        return true;

    if (!get_relocation_howto(input_bfd, r_type, &howto))
        return false;

    r_symndx = ELF32_R_SYM(rel->r_info);

    if (r_symndx < symtab_hdr->sh_info)
    {
        resolve_local_symbol(local_syms, local_sections, r_symndx,
                           output_bfd, rel, &sym, &sec, &relocation);
    }
    else
    {
        resolve_global_symbol(info, input_bfd, input_section, rel,
                            r_symndx, symtab_hdr, sym_hashes,
                            &h, &sec, &relocation, &unresolved_reloc);
    }

    if (sec != NULL && discarded_section(sec))
        RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                       rel, 1, relend, R_BFIN_UNUSED0,
                                       howto, 0, contents);

    if (bfd_link_relocatable(info))
        return true;

    address = rel->r_offset;

    switch (r_type)
    {
    case R_BFIN_GNU_VTINHERIT:
    case R_BFIN_GNU_VTENTRY:
        return true;

    case R_BFIN_GOT:
        if (h != NULL && strcmp(h->root.root.string, "__GLOBAL_OFFSET_TABLE_") == 0)
            break;

        relocation = process_got_relocation(dynobj, output_bfd, info, h, r_symndx,
                                           local_got_offsets, relocation,
                                           &unresolved_reloc);
        if (relocation == (bfd_vma)-1)
            return false;

        rel->r_addend = 0;
        relocation /= 4;
        break;
    }

    r = bfin_final_link_relocate(rel, howto, input_bfd, input_section,
                                contents, address, relocation, rel->r_addend);

    if (!handle_unresolved_relocation(info, input_bfd, input_section, rel, h,
                                     unresolved_reloc))
        return false;

    if (r != bfd_reloc_ok)
    {
        if (!handle_relocation_error(info, input_bfd, input_section, rel,
                                    h, sym, symtab_hdr, sec, howto, r))
            return false;
    }

    return true;
}

static int
bfin_relocate_section(bfd *output_bfd,
                     struct bfd_link_info *info,
                     bfd *input_bfd,
                     asection *input_section,
                     bfd_byte *contents,
                     Elf_Internal_Rela *relocs,
                     Elf_Internal_Sym *local_syms,
                     asection **local_sections)
{
    bfd *dynobj;
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    bfd_vma *local_got_offsets;
    Elf_Internal_Rela *rel;
    Elf_Internal_Rela *relend;

    dynobj = elf_hash_table(info)->dynobj;
    symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    sym_hashes = elf_sym_hashes(input_bfd);
    local_got_offsets = elf_local_got_offsets(input_bfd);

    rel = relocs;
    relend = relocs + input_section->reloc_count;
    
    for (; rel < relend; rel++)
    {
        if (!process_single_relocation(output_bfd, info, input_bfd, input_section,
                                      contents, rel, relend, local_syms,
                                      local_sections, symtab_hdr, sym_hashes,
                                      local_got_offsets, &dynobj))
            return false;
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
  if (h != NULL)
    {
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_BFIN_GNU_VTINHERIT || r_type == R_BFIN_GNU_VTENTRY)
        return NULL;
    }

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
  struct bfinfdpic_elf_link_hash_table *ret;
  size_t amt = sizeof (struct bfinfdpic_elf_link_hash_table);

  ret = bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd,
				      _bfd_elf_link_hash_newfunc,
				      sizeof (struct elf_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  return &ret->elf.root;
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
static hashval_t
bfinfdpic_relocs_info_hash (const void *entry_)
{
  const struct bfinfdpic_relocs_info *entry = entry_;
  const long ABFD_HASH_MULTIPLIER = 257;
  
  long base_hash = (entry->symndx == -1)
                   ? (long) entry->d.h->root.root.hash
                   : entry->symndx + (long) entry->d.abfd->id * ABFD_HASH_MULTIPLIER;
  
  return base_hash + entry->addend;
}

/* Test whether the key fields of two bfinfdpic_relocs_info entries are
   identical.  */
static int
bfinfdpic_relocs_info_eq (const void *entry1, const void *entry2)
{
  const struct bfinfdpic_relocs_info *e1 = entry1;
  const struct bfinfdpic_relocs_info *e2 = entry2;

  if (e1->symndx != e2->symndx || e1->addend != e2->addend)
    return 0;

  if (e1->symndx == -1)
    return e1->d.h == e2->d.h;
  
  return e1->d.abfd == e2->d.abfd;
}

/* Find or create an entry in a hash table HT that matches the key
   fields of the given ENTRY.  If it's not found, memory for a new
   entry is allocated in ABFD's obstack.  */
static struct bfinfdpic_relocs_info *
allocate_relocs_info(bfd *abfd, const struct bfinfdpic_relocs_info *entry)
{
  struct bfinfdpic_relocs_info *new_info = bfd_zalloc(abfd, sizeof(*new_info));
  
  if (!new_info)
    return NULL;
  
  new_info->symndx = entry->symndx;
  new_info->d = entry->d;
  new_info->addend = entry->addend;
  new_info->plt_entry = (bfd_vma)-1;
  new_info->lzplt_entry = (bfd_vma)-1;
  
  return new_info;
}

static struct bfinfdpic_relocs_info *
bfinfdpic_relocs_info_find (struct htab *ht,
			   bfd *abfd,
			   const struct bfinfdpic_relocs_info *entry,
			   enum insert_option insert)
{
  struct bfinfdpic_relocs_info **loc;

  if (!ht)
    return NULL;

  loc = (struct bfinfdpic_relocs_info **) htab_find_slot (ht, entry, insert);

  if (!loc)
    return NULL;

  if (*loc)
    return *loc;

  *loc = allocate_relocs_info(abfd, entry);
  return *loc;
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
  struct bfinfdpic_relocs_info entry;

  entry.symndx = -1;
  entry.d.h = h;
  entry.addend = addend;

  return bfinfdpic_relocs_info_find (ht, abfd, &entry, insert);
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
  struct bfinfdpic_relocs_info entry;

  entry.symndx = symndx;
  entry.d.abfd = abfd;
  entry.addend = addend;

  return bfinfdpic_relocs_info_find (ht, abfd, &entry, insert);
}

/* Merge fields set by check_relocs() of two entries that end up being
   mapped to the same (presumably global) symbol.  */

inline static void
bfinfdpic_pic_merge_early_relocs_info (struct bfinfdpic_relocs_info *e2,
				       struct bfinfdpic_relocs_info const *e1)
{
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
  BFD_ASSERT (reloc_offset < sreloc->size);
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
_bfinfdpic_add_rofixup (bfd *output_bfd, asection *rofixup, bfd_vma offset,
			struct bfinfdpic_relocs_info *entry)
{
  #define FIXUP_ENTRY_SIZE 4
  bfd_vma fixup_offset;

  if (rofixup->flags & SEC_EXCLUDE)
    return -1;

  fixup_offset = rofixup->reloc_count * FIXUP_ENTRY_SIZE;
  if (rofixup->contents)
    {
      BFD_ASSERT (fixup_offset < rofixup->size);
      bfd_put_32 (output_bfd, offset, rofixup->contents + fixup_offset);
    }
  rofixup->reloc_count++;

  if (entry && entry->symndx)
    {
      BFD_ASSERT (entry->fixups > 0);
      entry->fixups--;
    }

  return fixup_offset;
}

/* Find the segment number in which OSEC, and output section, is
   located.  */

static unsigned
_bfinfdpic_osec_to_segment (bfd *output_bfd, asection *osec)
{
  Elf_Internal_Phdr *p = _bfd_elf_find_segment_containing_section (output_bfd, osec);

  return (p != NULL) ? p - elf_tdata (output_bfd)->phdr : -1;
}

inline static bool
_bfinfdpic_osec_readonly_p (bfd *output_bfd, asection *osec)
{
  unsigned seg = _bfinfdpic_osec_to_segment (output_bfd, osec);
  Elf_Internal_Phdr *phdr = elf_tdata (output_bfd)->phdr;
  
  return !(phdr[seg].p_flags & PF_W);
}

/* Generate relocations for GOT entries, function descriptors, and
   code for PLT and lazy PLT entries.  */

inline static bool
_bfinfdpic_emit_got_relocs_plt_entries (struct bfinfdpic_relocs_info *entry,
					bfd *output_bfd,
					struct bfd_link_info *info,
					asection *sec,
					Elf_Internal_Sym *sym,
					bfd_vma addend)
{
  bfd_vma fd_lazy_rel_offset = (bfd_vma) -1;
  int dynindx = -1;

  if (entry->done)
    return true;
  entry->done = 1;

  if (entry->got_entry || entry->fdgot_entry || entry->fd_entry)
    dynindx = _bfinfdpic_get_dynindx(entry, sec);

  if (entry->got_entry)
    _bfinfdpic_emit_got_entry(entry, output_bfd, info, sec, sym, addend, dynindx);

  if (entry->fdgot_entry)
    _bfinfdpic_emit_fdgot_entry(entry, output_bfd, info, addend, dynindx);

  if (entry->fd_entry)
    fd_lazy_rel_offset = _bfinfdpic_emit_fd_entry(entry, output_bfd, info, sec, sym, addend, dynindx);

  if (entry->plt_entry != (bfd_vma) -1)
    _bfinfdpic_emit_plt_entry(entry, info);

  if (entry->lzplt_entry != (bfd_vma) -1)
    _bfinfdpic_emit_lzplt_entry(entry, info, fd_lazy_rel_offset);

  return true;
}

static int
_bfinfdpic_get_dynindx(struct bfinfdpic_relocs_info *entry, asection *sec)
{
  if (entry->symndx == -1 && entry->d.h->dynindx != -1)
    return entry->d.h->dynindx;
  
  if (sec && sec->output_section 
      && !bfd_is_abs_section(sec->output_section)
      && !bfd_is_und_section(sec->output_section))
    return elf_section_data(sec->output_section)->dynindx;
  
  return 0;
}

static void
_bfinfdpic_emit_got_entry(struct bfinfdpic_relocs_info *entry,
                          bfd *output_bfd,
                          struct bfd_link_info *info,
                          asection *sec,
                          Elf_Internal_Sym *sym,
                          bfd_vma addend,
                          int dynindx)
{
  int idx = dynindx;
  bfd_vma ad = addend;
  
  if (sec && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
      ad = _bfinfdpic_calc_local_address(entry, sym, sec, addend);
      idx = _bfinfdpic_get_section_dynindx(sec);
    }

  bfd_vma got_offset = bfinfdpic_got_initial_offset(info) + entry->got_entry;
  bfd_vma got_addr = bfinfdpic_got_section(info)->output_section->vma 
                     + bfinfdpic_got_section(info)->output_offset + got_offset;

  if (bfd_link_pde(info) && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
      if (sec)
        ad += sec->output_section->vma;
      if (entry->symndx != -1 || entry->d.h->root.type != bfd_link_hash_undefweak)
        _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info), got_addr, entry);
    }
  else
    {
      bfd_vma offset = _bfd_elf_section_offset(output_bfd, info,
                                               bfinfdpic_got_section(info), got_offset);
      _bfinfdpic_add_dyn_reloc(output_bfd, bfinfdpic_gotrel_section(info),
                              offset + got_addr, R_BFIN_BYTE4_DATA, idx, ad, entry);
    }

  bfd_put_32(output_bfd, ad, bfinfdpic_got_section(info)->contents + got_offset);
}

static void
_bfinfdpic_emit_fdgot_entry(struct bfinfdpic_relocs_info *entry,
                            bfd *output_bfd,
                            struct bfd_link_info *info,
                            bfd_vma addend,
                            int dynindx)
{
  int reloc, idx;
  bfd_vma ad = 0;

  if (!(entry->symndx == -1 && entry->d.h->root.type == bfd_link_hash_undefweak 
        && BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
      if (entry->symndx == -1 && !BFINFDPIC_FUNCDESC_LOCAL(info, entry->d.h) 
          && BFINFDPIC_SYM_LOCAL(info, entry->d.h) && !bfd_link_pde(info))
        {
          reloc = R_BFIN_FUNCDESC;
          idx = elf_section_data(entry->d.h->root.u.def.section->output_section)->dynindx;
          ad = entry->d.h->root.u.def.section->output_offset + entry->d.h->root.u.def.value;
        }
      else if (entry->symndx == -1 && !BFINFDPIC_FUNCDESC_LOCAL(info, entry->d.h))
        {
          reloc = R_BFIN_FUNCDESC;
          idx = dynindx;
          ad = addend;
        }
      else
        {
          if (elf_hash_table(info)->dynamic_sections_created)
            BFD_ASSERT(entry->privfd);
          reloc = R_BFIN_BYTE4_DATA;
          idx = elf_section_data(bfinfdpic_got_section(info)->output_section)->dynindx;
          ad = bfinfdpic_got_section(info)->output_offset 
               + bfinfdpic_got_initial_offset(info) + entry->fd_entry;
        }

      bfd_vma fdgot_offset = bfinfdpic_got_initial_offset(info) + entry->fdgot_entry;
      bfd_vma fdgot_addr = bfinfdpic_got_section(info)->output_section->vma 
                           + bfinfdpic_got_section(info)->output_offset + fdgot_offset;

      if (bfd_link_pde(info) && (entry->symndx != -1 || BFINFDPIC_FUNCDESC_LOCAL(info, entry->d.h)))
        {
          ad += bfinfdpic_got_section(info)->output_section->vma;
          _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info), fdgot_addr, entry);
        }
      else
        {
          bfd_vma offset = _bfd_elf_section_offset(output_bfd, info,
                                                   bfinfdpic_got_section(info), fdgot_offset);
          _bfinfdpic_add_dyn_reloc(output_bfd, bfinfdpic_gotrel_section(info),
                                  offset + fdgot_addr, reloc, idx, ad, entry);
        }
    }

  bfd_put_32(output_bfd, ad, bfinfdpic_got_section(info)->contents 
             + bfinfdpic_got_initial_offset(info) + entry->fdgot_entry);
}

static bfd_vma
_bfinfdpic_emit_fd_entry(struct bfinfdpic_relocs_info *entry,
                        bfd *output_bfd,
                        struct bfd_link_info *info,
                        asection *sec,
                        Elf_Internal_Sym *sym,
                        bfd_vma addend,
                        int dynindx)
{
  int idx = dynindx;
  bfd_vma ad = addend;
  bfd_vma ofst;
  long lowword, highword;
  bfd_vma fd_lazy_rel_offset = (bfd_vma) -1;

  if (sec && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
      ad = _bfinfdpic_calc_local_address(entry, sym, sec, addend);
      idx = _bfinfdpic_get_section_dynindx(sec);
    }

  bfd_vma fd_offset = bfinfdpic_got_initial_offset(info) + entry->fd_entry;
  bfd_vma fd_addr = bfinfdpic_got_section(info)->output_section->vma 
                    + bfinfdpic_got_section(info)->output_offset + fd_offset;

  if (bfd_link_pde(info) && (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(info, entry->d.h)))
    {
      if (sec)
        ad += sec->output_section->vma;
      ofst = 0;
      if (entry->symndx != -1 || entry->d.h->root.type != bfd_link_hash_undefweak)
        {
          _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info), fd_addr, entry);
          _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info), fd_addr + 4, entry);
        }
    }
  else
    {
      asection *reloc_sec = entry->lazyplt ? bfinfdpic_pltrel_section(info) 
                                           : bfinfdpic_gotrel_section(info);
      bfd_vma offset = _bfd_elf_section_offset(output_bfd, info,
                                               bfinfdpic_got_section(info), fd_offset);
      ofst = _bfinfdpic_add_dyn_reloc(output_bfd, reloc_sec, offset + fd_addr,
                                      R_BFIN_FUNCDESC_VALUE, idx, ad, entry);
    }

  _bfinfdpic_calc_fd_words(entry, output_bfd, info, sec, ad, ofst, 
                          &lowword, &highword, &fd_lazy_rel_offset);

  bfd_put_32(output_bfd, lowword, bfinfdpic_got_section(info)->contents + fd_offset);
  bfd_put_32(output_bfd, highword, bfinfdpic_got_section(info)->contents + fd_offset + 4);

  return fd_lazy_rel_offset;
}

static void
_bfinfdpic_calc_fd_words(struct bfinfdpic_relocs_info *entry,
                        bfd *output_bfd,
                        struct bfd_link_info *info,
                        asection *sec,
                        bfd_vma ad,
                        bfd_vma ofst,
                        long *lowword,
                        long *highword,
                        bfd_vma *fd_lazy_rel_offset)
{
  if (bfd_link_pde(info) && sec && sec->output_section)
    {
      *lowword = ad;
      *highword = bfinfdpic_got_section(info)->output_section->vma
                  + bfinfdpic_got_section(info)->output_offset
                  + bfinfdpic_got_initial_offset(info);
    }
  else if (entry->lazyplt)
    {
      *fd_lazy_rel_offset = ofst;
      *lowword = entry->lzplt_entry + 4
                 + bfinfdpic_plt_section(info)->output_offset
                 + bfinfdpic_plt_section(info)->output_section->vma;
      *highword = _bfinfdpic_osec_to_segment(output_bfd, 
                                             bfinfdpic_plt_section(info)->output_section);
    }
  else
    {
      *lowword = ad;
      if (sec == NULL || (entry->symndx == -1 && entry->d.h->dynindx != -1 
                         && entry->d.h->dynindx == ofst))
        *highword = 0;
      else
        *highword = _bfinfdpic_osec_to_segment(output_bfd, sec->output_section);
    }
}

static void
_bfinfdpic_emit_plt_entry(struct bfinfdpic_relocs_info *entry,
                         struct bfd_link_info *info)
{
  bfd_byte *plt_code = bfinfdpic_plt_section(info)->contents + entry->plt_entry;

  BFD_ASSERT(entry->fd_entry);

  if (entry->fd_entry >= -(1 << 17) && entry->fd_entry + 4 < (1 << 17))
    {
      bfd_put_32(output_bfd, 0xe519 | ((entry->fd_entry << 14) & 0xFFFF0000), plt_code);
      bfd_put_32(output_bfd, 0xe51b | (((entry->fd_entry + 4) << 14) & 0xFFFF0000), plt_code + 4);
    }
  else
    {
      bfd_put_32(output_bfd, 0xe109 | (entry->fd_entry << 16), plt_code);
      bfd_put_32(output_bfd, 0xe149 | (entry->fd_entry & 0xFFFF0000), plt_code + 4);
      bfd_put_16(output_bfd, 0x5ad9, plt_code + 8);
      bfd_put_16(output_bfd, 0x9159, plt_code + 10);
      bfd_put_16(output_bfd, 0xac5b, plt_code + 12);
      plt_code += 14;
      bfd_put_16(output_bfd, 0x0051, plt_code);
      return;
    }
  bfd_put_16(output_bfd, 0x0051, plt_code + 8);
}

#define LZPLT_NORMAL_SIZE 6
#define LZPLT_RESOLVER_EXTRA 6

static void
_bfinfdpic_emit_lzplt_entry(struct bfinfdpic_relocs_info *entry,
                           struct bfd_link_info *info,
                           bfd_vma fd_lazy_rel_offset)
{
  bfd_byte *lzplt_code = bfinfdpic_plt_section(info)->contents + entry->lzplt_entry;
  bfd_vma resolverStub_addr;

  bfd_put_32(output_bfd, fd_lazy_rel_offset, lzplt_code);
  lzplt_code += 4;

  resolverStub_addr = entry->lzplt_entry / BFINFDPIC_LZPLT_BLOCK_SIZE
                     * BFINFDPIC_LZPLT_BLOCK_SIZE + BFINFDPIC_LZPLT_RESOLV_LOC;
  
  if (resolverStub_addr >= bfinfdpic_plt_initial_offset(info))
    resolverStub_addr = bfinfdpic_plt_initial_offset(info) - LZPLT_NORMAL_SIZE - LZPLT_RESOLVER_EXTRA;

  if (entry->lzplt_entry == resolverStub_addr)
    {
      bfd_put_32(output_bfd, 0xa05b915a, lzplt_code);
      bfd_put_16(output_bfd, 0x0052, lzplt_code + 4);
    }
  else
    {
      bfd_vma jump_offset = ((resolverStub_addr - entry->lzplt_entry) / 2) & 0xFFF;
      bfd_put_16(output_bfd, 0x2000 | jump_offset, lzplt_code);
    }
}

static bfd_vma
_bfinfdpic_calc_local_address(struct bfinfdpic_relocs_info *entry,
                             Elf_Internal_Sym *sym,
                             asection *sec,
                             bfd_vma addend)
{
  bfd_vma ad = addend;
  if (entry->symndx == -1)
    ad += entry->d.h->root.u.def.value;
  else
    ad += sym->st_value;
  ad += sec->output_offset;
  return ad;
}

static int
_bfinfdpic_get_section_dynindx(asection *sec)
{
  if (sec->output_section && elf_section_data(sec->output_section))
    return elf_section_data(sec->output_section)->dynindx;
  return 0;
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

#define SECTION_IS_ALLOC_LOAD(sec) \
  ((bfd_section_flags(sec) & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD))

#define UNDEFINED_WEAK_SYMBOL(h) \
  (h && h->root.type == bfd_link_hash_undefweak)

#define SHIFT_RIGHT_16 16
#define MASK_16BIT 0xffff
#define FILENAME_CRT0 "crt0.o"
#define FILENAME_CRT0_LEN 6
#define FILENAME_CRT0_SUFFIX_LEN 7

static void initialize_segments(bfd *output_bfd, struct bfd_link_info *info,
                                asection *input_section, unsigned *isec_segment,
                                unsigned *got_segment, unsigned *plt_segment)
{
  *isec_segment = _bfinfdpic_osec_to_segment(output_bfd, input_section->output_section);
  
  if (IS_FDPIC(output_bfd) && bfinfdpic_got_section(info))
    *got_segment = _bfinfdpic_osec_to_segment(output_bfd,
                                              bfinfdpic_got_section(info)->output_section);
  else
    *got_segment = -1;
  
  if (IS_FDPIC(output_bfd) && elf_hash_table(info)->dynamic_sections_created)
    *plt_segment = _bfinfdpic_osec_to_segment(output_bfd,
                                              bfinfdpic_plt_section(info)->output_section);
  else
    *plt_segment = -1;
}

static bool get_symbol_info(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr,
                            struct elf_link_hash_entry **sym_hashes,
                            Elf_Internal_Sym *local_syms, asection **local_sections,
                            unsigned long r_symndx, struct bfd_link_info *info,
                            asection *input_section, Elf_Internal_Rela *rel,
                            Elf_Internal_Sym **sym, struct elf_link_hash_entry **h,
                            asection **sec, asection **osec, bfd_vma *relocation,
                            const char **name)
{
  *h = NULL;
  *sym = NULL;
  *sec = NULL;
  
  if (r_symndx < symtab_hdr->sh_info)
  {
    *sym = local_syms + r_symndx;
    *osec = *sec = local_sections[r_symndx];
    *relocation = _bfd_elf_rela_local_sym(input_bfd, output_bfd, *sym, sec, rel);
    
    *name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, (*sym)->st_name);
    *name = *name == NULL ? bfd_section_name(*sec) : *name;
  }
  else
  {
    bool warned, ignored, unresolved_reloc;
    
    RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                            r_symndx, symtab_hdr, sym_hashes,
                            *h, *sec, *relocation,
                            unresolved_reloc, warned, ignored);
    *osec = *sec;
  }
  
  return true;
}

static bool check_readonly_section(bfd *output_bfd, asection *input_section,
                                   struct bfd_link_info *info, const char *message,
                                   const char *name, bfd *input_bfd,
                                   Elf_Internal_Rela *rel)
{
  if (_bfinfdpic_osec_readonly_p(output_bfd, input_section->output_section))
  {
    info->callbacks->warning(info, message, name, input_bfd, input_section, rel->r_offset);
    return false;
  }
  return true;
}

static bool emit_fixup_if_needed(bfd *output_bfd, struct bfd_link_info *info,
                                 asection *input_section, bfd_vma offset,
                                 struct bfinfdpic_relocs_info *picrel)
{
  if (offset != (bfd_vma)-1)
    _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info),
                          offset + input_section->output_section->vma
                          + input_section->output_offset, picrel);
  return true;
}

static bool emit_dynamic_reloc_if_needed(bfd *output_bfd, struct bfd_link_info *info,
                                         asection *input_section, bfd_vma offset,
                                         int r_type, int dynindx, bfd_vma addend,
                                         struct bfinfdpic_relocs_info *picrel)
{
  if (offset != (bfd_vma)-1)
    _bfinfdpic_add_dyn_reloc(output_bfd, bfinfdpic_gotrel_section(info),
                            offset + input_section->output_section->vma
                            + input_section->output_offset,
                            r_type, dynindx, addend, picrel);
  return true;
}

static bool handle_funcdesc_relocation(bfd *output_bfd, struct bfd_link_info *info,
                                       bfd *input_bfd, asection *input_section,
                                       bfd_byte *contents, Elf_Internal_Rela *rel,
                                       struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                                       asection *osec, asection *sec,
                                       struct bfinfdpic_relocs_info *picrel,
                                       bfd_vma *relocation, const char *name,
                                       unsigned *check_segment, unsigned got_segment)
{
  int dynindx;
  bfd_vma addend = rel->r_addend;
  bfd_vma offset;
  
  if ((input_section->flags & SEC_ALLOC) == 0)
  {
    check_segment[0] = check_segment[1] = got_segment;
    return true;
  }
  
  if (!UNDEFINED_WEAK_SYMBOL(h) || !BFINFDPIC_SYM_LOCAL(info, h))
  {
    if (h && !BFINFDPIC_FUNCDESC_LOCAL(info, h) && BFINFDPIC_SYM_LOCAL(info, h) && !bfd_link_pde(info))
    {
      dynindx = elf_section_data(h->root.u.def.section->output_section)->dynindx;
      addend += h->root.u.def.section->output_offset + h->root.u.def.value;
    }
    else if (h && !BFINFDPIC_FUNCDESC_LOCAL(info, h))
    {
      if (addend)
      {
        info->callbacks->warning(info, _("R_BFIN_FUNCDESC references dynamic symbol with nonzero addend"),
                                name, input_bfd, input_section, rel->r_offset);
        return false;
      }
      dynindx = h->dynindx;
    }
    else
    {
      BFD_ASSERT(picrel->privfd);
      dynindx = elf_section_data(bfinfdpic_got_section(info)->output_section)->dynindx;
      addend = bfinfdpic_got_section(info)->output_offset + bfinfdpic_got_initial_offset(info) + picrel->fd_entry;
    }
    
    if (bfd_link_pde(info) && (!h || BFINFDPIC_FUNCDESC_LOCAL(info, h)))
    {
      addend += bfinfdpic_got_section(info)->output_section->vma;
      if (SECTION_IS_ALLOC_LOAD(input_section->output_section))
      {
        if (!check_readonly_section(output_bfd, input_section, info,
                                    _("cannot emit fixups in read-only section"),
                                    name, input_bfd, rel))
          return false;
        
        offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
        emit_fixup_if_needed(output_bfd, info, input_section, offset, picrel);
      }
    }
    else if (SECTION_IS_ALLOC_LOAD(input_section->output_section))
    {
      if (!check_readonly_section(output_bfd, input_section, info,
                                  _("cannot emit dynamic relocations in read-only section"),
                                  name, input_bfd, rel))
        return false;
      
      offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
      emit_dynamic_reloc_if_needed(output_bfd, info, input_section, offset,
                                   R_BFIN_BYTE4_DATA, dynindx, addend, picrel);
    }
    else
      addend += bfinfdpic_got_section(info)->output_section->vma;
  }
  
  *relocation = addend - rel->r_addend;
  check_segment[0] = check_segment[1] = got_segment;
  return true;
}

static bool handle_funcdesc_value_relocation(bfd *output_bfd, struct bfd_link_info *info,
                                             bfd *input_bfd, asection *input_section,
                                             bfd_byte *contents, Elf_Internal_Rela *rel,
                                             struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                                             asection *osec, asection *sec,
                                             struct bfinfdpic_relocs_info *picrel,
                                             bfd_vma *relocation, const char *name,
                                             int r_type, unsigned *check_segment,
                                             unsigned got_segment)
{
  int dynindx;
  bfd_vma addend = rel->r_addend;
  bfd_vma offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
  
  if (h && !BFINFDPIC_SYM_LOCAL(info, h))
  {
    if (addend && r_type == R_BFIN_FUNCDESC_VALUE)
    {
      info->callbacks->warning(info, _("R_BFIN_FUNCDESC_VALUE references dynamic symbol with nonzero addend"),
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
    if (osec && osec->output_section && !bfd_is_abs_section(osec->output_section) && !bfd_is_und_section(osec->output_section))
      dynindx = elf_section_data(osec->output_section)->dynindx;
    else
      dynindx = 0;
  }
  
  if (bfd_link_pde(info) && (!h || BFINFDPIC_SYM_LOCAL(info, h)))
  {
    if (osec)
      addend += osec->output_section->vma;
    if (IS_FDPIC(input_bfd) && SECTION_IS_ALLOC_LOAD(input_section->output_section))
    {
      if (!check_readonly_section(output_bfd, input_section, info,
                                  _("cannot emit fixups in read-only section"),
                                  name, input_bfd, rel))
        return false;
      
      if (!UNDEFINED_WEAK_SYMBOL(h))
      {
        emit_fixup_if_needed(output_bfd, info, input_section, offset, picrel);
        if (r_type == R_BFIN_FUNCDESC_VALUE && offset != (bfd_vma)-1)
          _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info),
                                offset + input_section->output_section->vma
                                + input_section->output_offset + 4, picrel);
      }
    }
  }
  else
  {
    if (SECTION_IS_ALLOC_LOAD(input_section->output_section))
    {
      if (!check_readonly_section(output_bfd, input_section, info,
                                  _("cannot emit dynamic relocations in read-only section"),
                                  name, input_bfd, rel))
        return false;
      
      emit_dynamic_reloc_if_needed(output_bfd, info, input_section, offset,
                                   r_type, dynindx, addend, picrel);
    }
    else if (osec)
      addend += osec->output_section->vma;
    *relocation = addend - rel->r_addend;
  }
  
  if (r_type == R_BFIN_FUNCDESC_VALUE)
  {
    if (bfd_link_pde(info) && (!h || BFINFDPIC_SYM_LOCAL(info, h)))
      bfd_put_32(output_bfd,
                bfinfdpic_got_section(info)->output_section->vma
                + bfinfdpic_got_section(info)->output_offset
                + bfinfdpic_got_initial_offset(info),
                contents + rel->r_offset + 4);
    else
      bfd_put_32(output_bfd,
                h && !BFINFDPIC_SYM_LOCAL(info, h) ? 0
                : _bfinfdpic_osec_to_segment(output_bfd, sec->output_section),
                contents + rel->r_offset + 4);
  }
  
  check_segment[0] = check_segment[1] = got_segment;
  return true;
}

static void set_check_segments_for_pcrel(struct bfinfdpic_relocs_info *picrel,
                                         struct bfd_link_info *info,
                                         unsigned *check_segment,
                                         unsigned isec_segment, unsigned plt_segment,
                                         asection *sec, bfd *output_bfd)
{
  check_segment[0] = isec_segment;
  
  if (!IS_FDPIC(output_bfd))
    check_segment[1] = isec_segment;
  else if (picrel->plt)
  {
    check_segment[1] = plt_segment;
  }
  else if (picrel->symndx == -1 && picrel->d.h->root.type == bfd_link_hash_undefweak)
    check_segment[1] = check_segment[0];
  else
    check_segment[1] = sec ? _bfinfdpic_osec_to_segment(output_bfd, sec->output_section) : (unsigned)-1;
}

static void apply_relocation_adjustment(int r_type, bfd_vma *relocation, Elf_Internal_Rela *rel)
{
  switch (r_type)
  {
  case R_BFIN_GOTOFFHI:
    *relocation += rel->r_addend;
    /* Fall through */
  case R_BFIN_GOTHI:
  case R_BFIN_FUNCDESC_GOTHI:
  case R_BFIN_FUNCDESC_GOTOFFHI:
    *relocation >>= SHIFT_RIGHT_16;
    /* Fall through */
  case R_BFIN_GOTLO:
  case R_BFIN_FUNCDESC_GOTLO:
  case R_BFIN_GOTOFFLO:
  case R_BFIN_FUNCDESC_GOTOFFLO:
    *relocation &= MASK_16BIT;
    break;
  }
}

static void cancel_addend_if_needed(int r_type, struct bfinfdpic_relocs_info *picrel,
                                    bfd *output_bfd, bfd_vma *relocation,
                                    Elf_Internal_Rela *rel)
{
  switch (r_type)
  {
  case R_BFIN_PCREL24:
  case R_BFIN_PCREL24_JUMP_L:
    if (!IS_FDPIC(output_bfd) || !picrel->plt)
      break;
    /* Fall through */
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
    *relocation -= rel->r_addend;
    break;
  }
}

static bool check_filename_is_crt0(bfd *input_bfd)
{
  const char *filename = bfd_get_filename(input_bfd);
  size_t len = strlen(filename);
  
  return (len == FILENAME_CRT0_LEN && filename_cmp(filename, FILENAME_CRT0) == 0) ||
         (len > FILENAME_CRT0_LEN && filename_cmp(filename + len - FILENAME_CRT0_SUFFIX_LEN, "/crt0.o") == 0);
}

static void handle_segment_mismatch(struct bfd_link_info *info, bfd *output_bfd,
                                    bfd *input_bfd, asection *input_section,
                                    Elf_Internal_Rela *rel, unsigned *check_segment,
                                    struct bfinfdpic_relocs_info *picrel,
                                    int *silence_segment_error, const char *name)
{
  if (check_segment[0] != check_segment[1] && IS_FDPIC(output_bfd))
  {
    if (*silence_segment_error == 1)
      *silence_segment_error = check_filename_is_crt0(input_bfd) ? -1 : 0;
    
    if (!*silence_segment_error && 
        !(picrel && picrel->symndx == -1 && picrel->d.h->root.type == bfd_link_hash_undefined))
    {
      info->callbacks->warning(info,
                              bfd_link_pic(info)
                              ? _("relocations between different segments are not supported")
                              : _("warning: relocation references a different segment"),
                              name, input_bfd, input_section, rel->r_offset);
    }
    
    elf_elfheader(output_bfd)->e_flags |= EF_BFIN_PIC;
  }
}

static void handle_relocation_error(struct bfd_link_info *info, bfd_reloc_status_type r,
                                    struct elf_link_hash_entry *h, const char *name,
                                    reloc_howto_type *howto, bfd *input_bfd,
                                    asection *input_section, Elf_Internal_Rela *rel)
{
  const char *msg = NULL;
  
  switch (r)
  {
  case bfd_reloc_overflow:
    (*info->callbacks->reloc_overflow)(info, (h ? &h->root : NULL), name, howto->name,
                                       (bfd_vma)0, input_bfd, input_section, rel->r_offset);
    break;
  case bfd_reloc_undefined:
    (*info->callbacks->undefined_symbol)(info, name, input_bfd, input_section, rel->r_offset, true);
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
    (*info->callbacks->warning)(info, msg, name, input_bfd, input_section, rel->r_offset);
}

static int
bfinfdpic_relocate_section(bfd *output_bfd,
                           struct bfd_link_info *info,
                           bfd *input_bfd,
                           asection *input_section,
                           bfd_byte *contents,
                           Elf_Internal_Rela *relocs,
                           Elf_Internal_Sym *local_syms,
                           asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  unsigned isec_segment, got_segment, plt_segment, check_segment[2];
  int silence_segment_error = !bfd_link_pic(info);
  
  symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes(input_bfd);
  relend = relocs + input_section->reloc_count;
  
  initialize_segments(output_bfd, info, input_section, &isec_segment, &got_segment, &plt_segment);
  
  for (rel = relocs; rel < relend; rel++)
  {
    reloc_howto_type *howto;
    unsigned long r_symndx;
    Elf_Internal_Sym *sym;
    asection *sec;
    struct elf_link_hash_entry *h;
    bfd_vma relocation;
    bfd_reloc_status_type r;
    const char *name = NULL;
    int r_type;
    asection *osec;
    struct bfinfdpic_relocs_info *picrel;
    bfd_vma orig_addend = rel->r_addend;
    
    r_type = ELF32_R_TYPE(rel->r_info);
    
    if (r_type == R_BFIN_GNU_VTINHERIT || r_type == R_BFIN_GNU_VTENTRY)
      continue;
    
    r_symndx = ELF32_R_SYM(rel->r_info);
    howto = bfin_reloc_type_lookup(input_bfd, r_type);
    if (howto == NULL)
    {
      bfd_set_error(bfd_error_bad_value);
      return false;
    }
    
    picrel = NULL;
    get_symbol_info(input_bfd, symtab_hdr, sym_hashes, local_syms, local_sections,
                   r_symndx, info, input_section, rel, &sym, &h, &sec, &osec, &relocation, &name);
    
    if (sec != NULL && discarded_section(sec))
      RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                      rel, 1, relend, R_BFIN_UNUSED0,
                                      howto, 0, contents);
    
    if (bfd_link_relocatable(info))
      continue;
    
    if (h != NULL && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
        && !BFINFDPIC_SYM_LOCAL(info, h))
    {
      osec = sec = NULL;
      relocation = 0;
    }
    
    switch (r_type)
    {
    case R_BFIN_PCREL24:
    case R_BFIN_PCREL24_JUMP_L:
    case R_BFIN_BYTE4_DATA:
      if (!IS_FDPIC(output_bfd))
        goto non_fdpic;
      /* Fall through */
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
      if ((input_section->flags & SEC_ALLOC) == 0)
        break;
      
      if (h != NULL)
        picrel = bfinfdpic_relocs_info_for_global(bfinfdpic_relocs_info(info), input_bfd, h, orig_addend, INSERT);
      else
        picrel = bfinfdpic_relocs_info_for_local(bfinfdpic_relocs_info(info), input_bfd, r_symndx, orig_addend, INSERT);
      
      if (!picrel)
        return false;
      
      if (!_bfinfdpic_emit_got_relocs_plt_entries(picrel, output_bfd, info, osec, sym, rel->r_addend))
      {
        _bfd_error_handler(_("%pB: relocation at `%pA+%#" PRIx64 "' references symbol `%s' with nonzero addend"),
                          input_bfd, input_section, (uint64_t)rel->r_offset, name);
        return false;
      }
      break;
      
    default:
    non_fdpic:
      picrel = NULL;
      if (h && !BFINFDPIC_SYM_LOCAL(info, h) &&
          _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1)
      {
        info->callbacks->warning(info, _("relocation references symbol not defined in the module"),
                                name, input_bfd, input_section, rel->r_offset);
        return false;
      }
      break;
    }
    
    switch (r_type)
    {
    case R_BFIN_PCREL24:
    case R_BFIN_PCREL24_JUMP_L:
      if (picrel && picrel->plt)
      {
        relocation = bfinfdpic_plt_section(info)->output_section->vma
                    + bfinfdpic_plt_section(info)->output_offset
                    + picrel->plt_entry;
      }
      set_check_segments_for_pcrel(picrel, info, check_segment, isec_segment, plt_segment, sec, output_bfd);
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
      relocation -= bfinfdpic_got_section(info)->output_section->vma
                   + bfinfdpic_got_section(info)->output_offset
                   + bfinfdpic_got_initial_offset(info);
      check_segment[0] = got_segment;
      check_segment[1] = sec ? _bfinfdpic_osec_to_segment(output_bfd, sec->output_section) : (unsigned)-1;
      break;
      
    case R_BFIN_FUNCDESC_GOTOFF17M4:
    case R_BFIN_FUNCDESC_GOTOFFHI:
    case R_BFIN_FUNCDESC_GOTOFFLO:
      relocation = picrel->fd_entry;
      check_segment[0] = check_segment[1] = got_segment;
      break;
      
    case R_BFIN_FUNCDESC:
      if (!handle_funcdesc_relocation(output_bfd, info, input_bfd, input_section, contents, rel,
                                      h, sym, osec, sec, picrel, &relocation, name, check_segment, got_segment))
        return false;
      break;
      
    case R_BFIN_BYTE4_DATA:
      if (!IS_FDPIC(output_bfd))
      {
        check_segment[0] = check_segment[1] = -1;
        break;
      }
      /* Fall through */
    case R_BFIN_FUNCDESC_VALUE:
      if (!handle_funcdesc_value_relocation(output_bfd, info, input_bfd, input_section, contents, rel,
                                            h, sym, osec, sec, picrel, &relocation, name, r_type,
                                            check_segment, got_segment))
        return false;
      break;
      
    default:
      check_segment[0] = isec_segment;
      check_segment[1] = sec ? _bfinfdpic_osec_to_segment(output_bfd, sec->output_section) : (unsigned)-1;
      break;
    }
    
    handle_segment_mismatch(info, output_bfd, input_bfd, input_

/* We need dynamic symbols for every section, since segments can
   relocate independently.  */
static bool
_bfinfdpic_link_omit_section_dynsym (bfd *output_bfd ATTRIBUTE_UNUSED,
				    struct bfd_link_info *info ATTRIBUTE_UNUSED,
				    asection *p)
{
  unsigned int sh_type = elf_section_data (p)->this_hdr.sh_type;
  
  if (sh_type == SHT_PROGBITS || sh_type == SHT_NOBITS || sh_type == SHT_NULL)
    return false;
  
  return true;
}

/* Create  a .got section, as well as its additional info field.  This
   is almost entirely copied from
   elflink.c:_bfd_elf_create_got_section().  */

static bool
create_section_with_alignment(bfd *abfd, const char *name, flagword flags, int alignment)
{
    asection *s = bfd_make_section_anyway_with_flags(abfd, name, flags);
    if (s == NULL || !bfd_set_section_alignment(s, alignment))
        return false;
    return true;
}

static asection *
create_and_store_section(bfd *abfd, const char *name, flagword flags, int alignment)
{
    asection *s = bfd_make_section_anyway_with_flags(abfd, name, flags);
    if (s == NULL || !bfd_set_section_alignment(s, alignment))
        return NULL;
    return s;
}

static bool
create_global_offset_table_symbol(bfd *abfd, struct bfd_link_info *info, asection *s,
                                   const struct elf_backend_data *bed)
{
    if (!bed->want_got_sym)
        return true;

    struct elf_link_hash_entry *h = _bfd_elf_define_linkage_sym(abfd, info, s, "__GLOBAL_OFFSET_TABLE_");
    elf_hash_table(info)->hgot = h;
    if (h == NULL)
        return false;

    if (!bfd_elf_link_record_dynamic_symbol(info, h))
        return false;

    return true;
}

static bool
create_procedure_linkage_table_symbol(bfd *abfd, struct bfd_link_info *info, asection *s,
                                       const struct elf_backend_data *bed)
{
    if (!bed->want_plt_sym)
        return true;

    struct bfd_link_hash_entry *bh = NULL;
    if (!_bfd_generic_link_add_one_symbol(info, abfd, "__PROCEDURE_LINKAGE_TABLE_",
                                           BSF_GLOBAL, s, 0, NULL, false,
                                           get_elf_backend_data(abfd)->collect, &bh))
        return false;

    struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)bh;
    h->def_regular = 1;
    h->type = STT_OBJECT;

    if (!bfd_link_executable(info) && !bfd_elf_link_record_dynamic_symbol(info, h))
        return false;

    return true;
}

static bool
create_fdpic_sections(bfd *abfd, struct bfd_link_info *info, flagword flags)
{
    #define FDPIC_SECTION_ALIGNMENT 2
    
    bfinfdpic_relocs_info(info) = htab_try_create(1,
                                                   bfinfdpic_relocs_info_hash,
                                                   bfinfdpic_relocs_info_eq,
                                                   (htab_del)NULL);
    if (!bfinfdpic_relocs_info(info))
        return false;

    asection *s = create_and_store_section(abfd, ".rel.got", flags | SEC_READONLY, FDPIC_SECTION_ALIGNMENT);
    if (s == NULL)
        return false;
    bfinfdpic_gotrel_section(info) = s;

    s = create_and_store_section(abfd, ".rofixup", flags | SEC_READONLY, FDPIC_SECTION_ALIGNMENT);
    if (s == NULL)
        return false;
    bfinfdpic_gotfixup_section(info) = s;

    return true;
}

static flagword
compute_plt_flags(const struct elf_backend_data *bed, flagword base_flags)
{
    flagword pltflags = base_flags | SEC_CODE;
    
    if (bed->plt_not_loaded)
        pltflags &= ~(SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS);
    
    if (bed->plt_readonly)
        pltflags |= SEC_READONLY;
    
    return pltflags;
}

static bool
_bfin_create_got_section(bfd *abfd, struct bfd_link_info *info)
{
    #define GOT_ALIGNMENT 3
    
    asection *s = elf_hash_table(info)->sgot;
    if (s != NULL)
        return true;

    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    flagword flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY | SEC_LINKER_CREATED;

    s = create_and_store_section(abfd, ".got", flags, GOT_ALIGNMENT);
    if (s == NULL)
        return false;
    elf_hash_table(info)->sgot = s;

    if (!create_global_offset_table_symbol(abfd, info, s, bed))
        return false;

    s->size += bed->got_header_size;

    if (IS_FDPIC(abfd) && !create_fdpic_sections(abfd, info, flags))
        return false;

    flagword pltflags = compute_plt_flags(bed, flags);
    s = create_and_store_section(abfd, ".plt", pltflags, bed->plt_alignment);
    if (s == NULL)
        return false;
    bfinfdpic_plt_section(info) = s;

    if (!create_procedure_linkage_table_symbol(abfd, info, s, bed))
        return false;

    s = create_and_store_section(abfd, ".rel.plt", flags | SEC_READONLY, bed->s->log_file_align);
    if (s == NULL)
        return false;
    bfinfdpic_pltrel_section(info) = s;

    return true;
}

/* Make sure the got and plt sections exist, and that our pointers in
   the link hash table point to them.  */

static bool create_dynbss_section(bfd *abfd)
{
    asection *s = bfd_make_section_anyway_with_flags(abfd, ".dynbss",
                                                     SEC_ALLOC | SEC_LINKER_CREATED);
    return s != NULL;
}

static bool create_rela_bss_section(bfd *abfd, const struct elf_backend_data *bed)
{
    flagword flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
                     | SEC_LINKER_CREATED | SEC_READONLY);
    
    asection *s = bfd_make_section_anyway_with_flags(abfd, ".rela.bss", flags);
    if (s == NULL)
        return false;
    
    return bfd_set_section_alignment(s, bed->s->log_file_align);
}

static bool verify_bfin_sections(struct bfd_link_info *info)
{
    return bfinfdpic_got_section(info) && 
           bfinfdpic_gotrel_section(info) &&
           bfinfdpic_plt_section(info) &&
           bfinfdpic_pltrel_section(info);
}

static bool
elf32_bfinfdpic_create_dynamic_sections(bfd *abfd, struct bfd_link_info *info)
{
    const struct elf_backend_data *bed = get_elf_backend_data(abfd);

    if (!_bfin_create_got_section(abfd, info))
        return false;

    BFD_ASSERT(verify_bfin_sections(info));

    if (!bed->want_dynbss)
        return true;

    if (!create_dynbss_section(abfd))
        return false;

    if (bfd_link_pic(info))
        return true;

    return create_rela_bss_section(abfd, bed);
}

/* Compute the total GOT size required by each symbol in each range.
   Symbols may require up to 4 words in the GOT: an entry pointing to
   the symbol, an entry pointing to its function descriptor, and a
   private function descriptors taking two words.  */

static void
_bfinfdpic_allocate_got_entry(struct bfinfdpic_relocs_info *entry,
                              struct _bfinfdpic_dynamic_got_info *dinfo)
{
  if (entry->got17m4)
    dinfo->got17m4 += 4;
  else if (entry->gothilo)
    dinfo->gothilo += 4;
  else
    entry->relocs32--;
  entry->relocs32++;
}

static void
_bfinfdpic_allocate_fdgot_entry(struct bfinfdpic_relocs_info *entry,
                                struct _bfinfdpic_dynamic_got_info *dinfo)
{
  if (entry->fdgot17m4)
    dinfo->got17m4 += 4;
  else if (entry->fdgothilo)
    dinfo->gothilo += 4;
  else
    entry->relocsfd--;
  entry->relocsfd++;
}

static int
_bfinfdpic_needs_plt_entry(struct bfinfdpic_relocs_info *entry,
                           struct _bfinfdpic_dynamic_got_info *dinfo)
{
  return entry->call
    && entry->symndx == -1 
    && ! BFINFDPIC_SYM_LOCAL (dinfo->info, entry->d.h)
    && elf_hash_table (dinfo->info)->dynamic_sections_created;
}

static int
_bfinfdpic_needs_privfd(struct bfinfdpic_relocs_info *entry,
                       struct _bfinfdpic_dynamic_got_info *dinfo)
{
  return entry->plt
    || entry->fdgoff17m4 
    || entry->fdgoffhilo
    || ((entry->fd || entry->fdgot17m4 || entry->fdgothilo)
        && (entry->symndx != -1
            || BFINFDPIC_FUNCDESC_LOCAL (dinfo->info, entry->d.h)));
}

static int
_bfinfdpic_needs_lazyplt(struct bfinfdpic_relocs_info *entry,
                        struct _bfinfdpic_dynamic_got_info *dinfo)
{
  return entry->privfd
    && entry->symndx == -1 
    && ! BFINFDPIC_SYM_LOCAL (dinfo->info, entry->d.h)
    && ! (dinfo->info->flags & DF_BIND_NOW)
    && elf_hash_table (dinfo->info)->dynamic_sections_created;
}

static void
_bfinfdpic_allocate_function_descriptor(struct bfinfdpic_relocs_info *entry,
                                       struct _bfinfdpic_dynamic_got_info *dinfo)
{
  if (entry->fdgoff17m4)
    dinfo->fd17m4 += 8;
  else if (entry->privfd && entry->plt)
    dinfo->fdplt += 8;
  else if (entry->privfd)
    dinfo->fdhilo += 8;
  else
    entry->relocsfdv--;
  entry->relocsfdv++;
}

static void
_bfinfdpic_count_nontls_entries (struct bfinfdpic_relocs_info *entry,
				 struct _bfinfdpic_dynamic_got_info *dinfo)
{
  _bfinfdpic_allocate_got_entry(entry, dinfo);
  _bfinfdpic_allocate_fdgot_entry(entry, dinfo);

  entry->plt = _bfinfdpic_needs_plt_entry(entry, dinfo);
  entry->privfd = _bfinfdpic_needs_privfd(entry, dinfo);
  entry->lazyplt = _bfinfdpic_needs_lazyplt(entry, dinfo);

  _bfinfdpic_allocate_function_descriptor(entry, dinfo);

  if (entry->lazyplt)
    dinfo->lzplt += LZPLT_NORMAL_SIZE;
}

/* Compute the number of dynamic relocations and fixups that a symbol
   requires, and add (or subtract) from the grand and per-symbol
   totals.  */

static bool
_is_valid_for_fixup(struct bfinfdpic_relocs_info *entry, struct _bfinfdpic_dynamic_got_info *dinfo)
{
  return entry->symndx != -1 || entry->d.h->root.type != bfd_link_hash_undefweak;
}

static void
_count_relocs32_and_fdv(struct bfinfdpic_relocs_info *entry, 
                        struct _bfinfdpic_dynamic_got_info *dinfo,
                        bfd_vma *relocs, bfd_vma *fixups)
{
  if (entry->symndx != -1 || BFINFDPIC_SYM_LOCAL(dinfo->info, entry->d.h))
  {
    if (_is_valid_for_fixup(entry, dinfo))
      *fixups += entry->relocs32 + 2 * entry->relocsfdv;
  }
  else
    *relocs += entry->relocs32 + entry->relocsfdv;
}

static void
_count_relocsfd(struct bfinfdpic_relocs_info *entry,
               struct _bfinfdpic_dynamic_got_info *dinfo,
               bfd_vma *relocs, bfd_vma *fixups)
{
  if (entry->symndx != -1 || BFINFDPIC_FUNCDESC_LOCAL(dinfo->info, entry->d.h))
  {
    if (_is_valid_for_fixup(entry, dinfo))
      *fixups += entry->relocsfd;
  }
  else
    *relocs += entry->relocsfd;
}

static void
_apply_counts(struct bfinfdpic_relocs_info *entry,
             struct _bfinfdpic_dynamic_got_info *dinfo,
             bfd_vma relocs, bfd_vma fixups, bool subtract)
{
  if (subtract)
  {
    relocs = -relocs;
    fixups = -fixups;
  }
  
  entry->dynrelocs += relocs;
  entry->fixups += fixups;
  dinfo->relocs += relocs;
  dinfo->fixups += fixups;
}

static void
_bfinfdpic_count_relocs_fixups(struct bfinfdpic_relocs_info *entry,
                               struct _bfinfdpic_dynamic_got_info *dinfo,
                               bool subtract)
{
  bfd_vma relocs = 0, fixups = 0;

  if (!bfd_link_pde(dinfo->info))
  {
    relocs = entry->relocs32 + entry->relocsfd + entry->relocsfdv;
  }
  else
  {
    _count_relocs32_and_fdv(entry, dinfo, &relocs, &fixups);
    _count_relocsfd(entry, dinfo, &relocs, &fixups);
  }

  _apply_counts(entry, dinfo, relocs, fixups, subtract);
}

/* Compute the total GOT and PLT size required by each symbol in each range. *
   Symbols may require up to 4 words in the GOT: an entry pointing to
   the symbol, an entry pointing to its function descriptor, and a
   private function descriptors taking two words.  */

static int
_bfinfdpic_count_got_plt_entries (void **entryp, void *dinfo_)
{
  struct bfinfdpic_relocs_info *entry = *entryp;
  struct _bfinfdpic_dynamic_got_info *dinfo = dinfo_;

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
				   bfd_signed_vma odd,
				   bfd_signed_vma cur,
				   bfd_vma got,
				   bfd_vma fd,
				   bfd_vma fdplt,
				   bfd_vma wrap)
{
  bfd_signed_vma wrapmin = -wrap;

  gad->fdcur = fdcur;
  gad->cur = cur;

  odd = handle_odd_word_allocation(gad, odd, &got);
  odd = compute_unpaired_got_location(cur, &got, odd);
  
  gad->max = cur + got;
  gad->min = fdcur - fd;
  gad->fdplt = 0;

  adjust_function_descriptors_wrapping(gad, wrapmin, &fdplt);
  adjust_got_entries_wrapping(gad, wrap, &fdplt);
  
  odd = wrap_odd_if_needed(odd, gad);
  wrap_cur_if_at_max(gad);

  return odd;
}

static bfd_signed_vma handle_odd_word_allocation(struct _bfinfdpic_dynamic_got_alloc_data *gad,
                                                  bfd_signed_vma odd,
                                                  bfd_vma *got)
{
  if (odd && *got)
    {
      gad->odd = odd;
      *got -= 4;
      return 0;
    }
  gad->odd = 0;
  return odd;
}

static bfd_signed_vma compute_unpaired_got_location(bfd_signed_vma cur,
                                                     bfd_vma *got,
                                                     bfd_signed_vma odd)
{
  if (*got & 4)
    {
      odd = cur + *got;
      *got += 4;
    }
  return odd;
}

static void adjust_function_descriptors_wrapping(struct _bfinfdpic_dynamic_got_alloc_data *gad,
                                                  bfd_signed_vma wrapmin,
                                                  bfd_vma *fdplt)
{
  if (gad->min < wrapmin)
    {
      gad->max += wrapmin - gad->min;
      gad->min = wrapmin;
    }
  else if (*fdplt && gad->min > wrapmin)
    {
      bfd_vma fds = calculate_available_fds(gad->min - wrapmin, *fdplt);
      *fdplt -= fds;
      gad->min -= fds;
      gad->fdplt += fds;
    }
}

static void adjust_got_entries_wrapping(struct _bfinfdpic_dynamic_got_alloc_data *gad,
                                        bfd_vma wrap,
                                        bfd_vma *fdplt)
{
  if ((bfd_vma) gad->max > wrap)
    {
      gad->min -= gad->max - wrap;
      gad->max = wrap;
    }
  else if (*fdplt && (bfd_vma) gad->max < wrap)
    {
      bfd_vma fds = calculate_available_fds(wrap - gad->max, *fdplt);
      *fdplt -= fds;
      gad->max += fds;
      gad->fdplt += fds;
    }
}

static bfd_vma calculate_available_fds(bfd_vma available_space, bfd_vma fdplt)
{
  if (available_space < fdplt)
    return available_space;
  return fdplt;
}

static bfd_signed_vma wrap_odd_if_needed(bfd_signed_vma odd,
                                          struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  if (odd > gad->max)
    return gad->min + odd - gad->max;
  return odd;
}

static void wrap_cur_if_at_max(struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  if (gad->cur == gad->max)
    gad->cur = gad->min;
}

/* Compute the location of the next GOT entry, given the allocation
   data for a range.  */

inline static bfd_signed_vma
_bfinfdpic_get_got_entry (struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  if (gad->odd)
    {
      bfd_signed_vma ret = gad->odd;
      gad->odd = 0;
      return ret;
    }
  
  bfd_signed_vma ret = gad->cur;
  gad->odd = gad->cur + 4;
  gad->cur += 8;
  if (gad->cur == gad->max)
    gad->cur = gad->min;
  
  return ret;
}

/* Compute the location of the next function descriptor entry in the
   GOT, given the allocation data for a range.  */

inline static bfd_signed_vma
_bfinfdpic_get_fd_entry (struct _bfinfdpic_dynamic_got_alloc_data *gad)
{
  const bfd_signed_vma FD_ENTRY_SIZE = 8;
  
  if (gad->fdcur == gad->min)
    gad->fdcur = gad->max;
  return gad->fdcur -= FD_ENTRY_SIZE;
}

/* Assign GOT offsets for every GOT entry and function descriptor.
   Doing everything in a single pass is tricky.  */

static int
_bfinfdpic_assign_got_entries (void **entryp, void *info_)
{
  struct bfinfdpic_relocs_info *entry = *entryp;
  struct _bfinfdpic_dynamic_got_plt_info *dinfo = info_;

  _bfinfdpic_assign_got_entry(entry, dinfo);
  _bfinfdpic_assign_fdgot_entry(entry, dinfo);
  _bfinfdpic_assign_fd_entry(entry, dinfo);

  return 1;
}

static void
_bfinfdpic_assign_got_entry(struct bfinfdpic_relocs_info *entry,
                            struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
  if (entry->got17m4)
    entry->got_entry = _bfinfdpic_get_got_entry (&dinfo->got17m4);
  else if (entry->gothilo)
    entry->got_entry = _bfinfdpic_get_got_entry (&dinfo->gothilo);
}

static void
_bfinfdpic_assign_fdgot_entry(struct bfinfdpic_relocs_info *entry,
                              struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
  if (entry->fdgot17m4)
    entry->fdgot_entry = _bfinfdpic_get_got_entry (&dinfo->got17m4);
  else if (entry->fdgothilo)
    entry->fdgot_entry = _bfinfdpic_get_got_entry (&dinfo->gothilo);
}

static void
_bfinfdpic_assign_fd_entry(struct bfinfdpic_relocs_info *entry,
                           struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
  #define FD_ENTRY_SIZE 8
  
  if (entry->fdgoff17m4)
    {
      entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->got17m4);
      return;
    }
  
  if (entry->plt)
    {
      _bfinfdpic_assign_plt_fd_entry(entry, dinfo);
      return;
    }
  
  if (entry->privfd)
    entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->gothilo);
}

static void
_bfinfdpic_assign_plt_fd_entry(struct bfinfdpic_relocs_info *entry,
                                struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
  #define FD_ENTRY_SIZE 8
  
  if (dinfo->got17m4.fdplt)
    {
      dinfo->got17m4.fdplt -= FD_ENTRY_SIZE;
      entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->got17m4);
    }
  else
    {
      dinfo->gothilo.fdplt -= FD_ENTRY_SIZE;
      entry->fd_entry = _bfinfdpic_get_fd_entry (&dinfo->gothilo);
    }
}

/* Assign GOT offsets to private function descriptors used by PLT
   entries (or referenced by 32-bit offsets), as well as PLT entries
   and lazy PLT entries.  */

static void allocate_fd_entry(struct bfinfdpic_relocs_info *entry, struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
    if (dinfo->got17m4.fdplt) {
        entry->fd_entry = _bfinfdpic_get_fd_entry(&dinfo->got17m4);
        dinfo->got17m4.fdplt -= 8;
    } else {
        BFD_ASSERT(dinfo->gothilo.fdplt);
        entry->fd_entry = _bfinfdpic_get_fd_entry(&dinfo->gothilo);
        dinfo->gothilo.fdplt -= 8;
    }
}

static int calculate_plt_entry_size(int fd_entry)
{
    #define PLT_ENTRY_SMALL_SIZE 10
    #define PLT_ENTRY_LARGE_SIZE 16
    #define FD_ENTRY_MIN_RANGE (-(1 << 17))
    #define FD_ENTRY_MAX_RANGE ((1 << 17) - 1)
    
    if (fd_entry >= FD_ENTRY_MIN_RANGE && fd_entry + 4 < FD_ENTRY_MAX_RANGE)
        return PLT_ENTRY_SMALL_SIZE;
    return PLT_ENTRY_LARGE_SIZE;
}

static void allocate_plt_entry(struct bfinfdpic_relocs_info *entry, struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
    entry->plt_entry = bfinfdpic_plt_section(dinfo->g.info)->size;
    BFD_ASSERT(entry->fd_entry);
    int size = calculate_plt_entry_size(entry->fd_entry);
    bfinfdpic_plt_section(dinfo->g.info)->size += size;
}

static void allocate_lazy_plt_entry(struct bfinfdpic_relocs_info *entry, struct _bfinfdpic_dynamic_got_plt_info *dinfo)
{
    entry->lzplt_entry = dinfo->g.lzplt;
    dinfo->g.lzplt += LZPLT_NORMAL_SIZE;
    
    if (entry->lzplt_entry % BFINFDPIC_LZPLT_BLOCK_SIZE == BFINFDPIC_LZPLT_RESOLV_LOC)
        dinfo->g.lzplt += LZPLT_RESOLVER_EXTRA;
}

static int _bfinfdpic_assign_plt_entries(void **entryp, void *info_)
{
    struct bfinfdpic_relocs_info *entry = *entryp;
    struct _bfinfdpic_dynamic_got_plt_info *dinfo = info_;

    if (entry->privfd && entry->fd_entry == 0)
        allocate_fd_entry(entry, dinfo);

    if (entry->plt)
        allocate_plt_entry(entry, dinfo);

    if (entry->lazyplt)
        allocate_lazy_plt_entry(entry, dinfo);

    return 1;
}

/* Cancel out any effects of calling _bfinfdpic_assign_got_entries and
   _bfinfdpic_assign_plt_entries.  */

static int
_bfinfdpic_reset_got_plt_entries (void **entryp, void *ignore ATTRIBUTE_UNUSED)
{
  struct bfinfdpic_relocs_info *entry = *entryp;

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
static struct elf_link_hash_entry *
resolve_indirect_hash(struct elf_link_hash_entry *h)
{
    while (h->root.type == bfd_link_hash_indirect ||
           h->root.type == bfd_link_hash_warning)
        h = (struct elf_link_hash_entry *)h->root.u.i.link;
    return h;
}

static int
handle_unchanged_entry(struct bfinfdpic_relocs_info *entry,
                       struct elf_link_hash_entry *h)
{
    if (entry->d.h == h)
        return 1;
    return 0;
}

static int
merge_with_existing_entry(struct bfinfdpic_relocs_info *entry,
                          struct bfinfdpic_relocs_info *oentry,
                          void **entryp,
                          htab_t *htab)
{
    bfinfdpic_pic_merge_early_relocs_info(oentry, entry);
    htab_clear_slot(*htab, entryp);
    return 1;
}

static int
reinsert_entry_if_needed(struct bfinfdpic_relocs_info *entry,
                         void **entryp,
                         htab_t *htab,
                         void *p)
{
    if (!htab_find(*htab, entry))
    {
        htab_clear_slot(*htab, entryp);
        entryp = htab_find_slot(*htab, entry, INSERT);
        if (!*entryp)
            *entryp = entry;
        *(htab_t *)p = NULL;
        return 0;
    }
    return 1;
}

static int
_bfinfdpic_resolve_final_relocs_info(void **entryp, void *p)
{
    struct bfinfdpic_relocs_info *entry = *entryp;
    htab_t *htab = p;

    if (entry->symndx != -1)
        return 1;

    struct elf_link_hash_entry *h = resolve_indirect_hash(entry->d.h);

    if (handle_unchanged_entry(entry, h))
        return 1;

    struct bfinfdpic_relocs_info *oentry = 
        bfinfdpic_relocs_info_for_global(*htab, 0, h, entry->addend, NO_INSERT);

    if (oentry)
        return merge_with_existing_entry(entry, oentry, entryp, htab);

    entry->d.h = h;

    return reinsert_entry_if_needed(entry, entryp, htab, p);
}

/* Compute the total size of the GOT, the PLT, the dynamic relocations
   section and the rofixup section.  Assign locations for GOT and PLT
   entries.  */

#define INITIAL_ODD_OFFSET 12
#define BIT_RANGE_18 18
#define BIT_RANGE_32 32
#define WORD_SIZE 4
#define GOT_MIN_SIZE 12

static bfd_vma
calculate_limit_for_18bit_range(struct _bfinfdpic_dynamic_got_plt_info *gpinfop, bfd_signed_vma odd)
{
    bfd_vma limit = odd + gpinfop->g.got17m4 + gpinfop->g.fd17m4;
    bfd_vma max_18bit = (bfd_vma)1 << BIT_RANGE_18;
    
    if (limit < max_18bit)
        limit = max_18bit - limit;
    else
        limit = 0;
    
    if (gpinfop->g.fdplt < limit)
        limit = gpinfop->g.fdplt;
    
    return limit;
}

static bfd_signed_vma
compute_got_allocations(struct _bfinfdpic_dynamic_got_plt_info *gpinfop, bfd_vma limit)
{
    bfd_signed_vma odd = INITIAL_ODD_OFFSET;
    
    odd = _bfinfdpic_compute_got_alloc_data(&gpinfop->got17m4,
                                           0,
                                           odd,
                                           16,
                                           gpinfop->g.got17m4,
                                           gpinfop->g.fd17m4,
                                           limit,
                                           (bfd_vma)1 << (BIT_RANGE_18 - 1));
    
    odd = _bfinfdpic_compute_got_alloc_data(&gpinfop->gothilo,
                                           gpinfop->got17m4.min,
                                           odd,
                                           gpinfop->got17m4.max,
                                           gpinfop->g.gothilo,
                                           gpinfop->g.fdhilo,
                                           gpinfop->g.fdplt - gpinfop->got17m4.fdplt,
                                           (bfd_vma)1 << (BIT_RANGE_32 - 1));
    
    return odd;
}

static bfd_vma
calculate_got_section_size(struct _bfinfdpic_dynamic_got_plt_info *gpinfop, bfd_signed_vma odd)
{
    bfd_vma size = gpinfop->gothilo.max - gpinfop->gothilo.min;
    
    if (odd + WORD_SIZE == gpinfop->gothilo.max)
        size -= WORD_SIZE;
    
    return size;
}

static bool
allocate_section_contents(asection *section, bfd *dynobj, bfd_vma size)
{
    section->size = size;
    
    if (size == 0) {
        section->flags |= SEC_EXCLUDE;
        return true;
    }
    
    section->contents = (bfd_byte *) bfd_zalloc(dynobj, size);
    if (section->contents == NULL)
        return false;
    
    section->alloced = 1;
    return true;
}

static bool
setup_got_section(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop, 
                  bfd_signed_vma odd, bfd *dynobj)
{
    asection *got = bfinfdpic_got_section(info);
    bfd_vma size = calculate_got_section_size(gpinfop, odd);
    
    if (size == GOT_MIN_SIZE && !elf_hash_table(info)->dynamic_sections_created) {
        got->flags |= SEC_EXCLUDE;
        got->size = 0;
        return true;
    }
    
    return allocate_section_contents(got, dynobj, size);
}

static bool
setup_gotrel_section(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop,
                     bfd *dynobj, bfd *output_bfd)
{
    asection *gotrel = bfinfdpic_gotrel_section(info);
    bfd_vma size = 0;
    
    if (elf_hash_table(info)->dynamic_sections_created) {
        bfd_vma rel_count = gpinfop->g.relocs - gpinfop->g.lzplt / LZPLT_NORMAL_SIZE;
        size = rel_count * get_elf_backend_data(output_bfd)->s->sizeof_rel;
    } else {
        BFD_ASSERT(gpinfop->g.relocs == 0);
    }
    
    return allocate_section_contents(gotrel, dynobj, size);
}

static bool
setup_gotfixup_section(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop,
                       bfd *dynobj)
{
    asection *gotfixup = bfinfdpic_gotfixup_section(info);
    bfd_vma size = (gpinfop->g.fixups + 1) * WORD_SIZE;
    
    return allocate_section_contents(gotfixup, dynobj, size);
}

static bool
setup_pltrel_section(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop,
                     bfd *dynobj, bfd *output_bfd)
{
    asection *pltrel = bfinfdpic_pltrel_section(info);
    bfd_vma size = 0;
    
    if (elf_hash_table(info)->dynamic_sections_created)
        size = gpinfop->g.lzplt / LZPLT_NORMAL_SIZE * get_elf_backend_data(output_bfd)->s->sizeof_rel;
    
    return allocate_section_contents(pltrel, dynobj, size);
}

static void
calculate_plt_section_size(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop)
{
    if (elf_hash_table(info)->dynamic_sections_created) {
        bfd_vma blocks = (gpinfop->g.lzplt + (BFINFDPIC_LZPLT_BLOCK_SIZE - WORD_SIZE) - LZPLT_NORMAL_SIZE)
                        / (BFINFDPIC_LZPLT_BLOCK_SIZE - WORD_SIZE);
        bfinfdpic_plt_section(info)->size = gpinfop->g.lzplt + blocks * LZPLT_RESOLVER_EXTRA;
    }
}

static void
setup_got_and_plt_offsets(struct bfd_link_info *info, struct _bfinfdpic_dynamic_got_plt_info *gpinfop,
                          bfd *output_bfd)
{
    bfinfdpic_got_initial_offset(info) = -gpinfop->gothilo.min;
    
    if (get_elf_backend_data(output_bfd)->want_got_sym)
        elf_hash_table(info)->hgot->root.u.def.value = bfinfdpic_got_initial_offset(info);
    
    if (elf_hash_table(info)->dynamic_sections_created)
        bfinfdpic_plt_initial_offset(info) = bfinfdpic_plt_section(info)->size;
}

static bool
allocate_plt_section(struct bfd_link_info *info, bfd *dynobj)
{
    asection *plt = bfinfdpic_plt_section(info);
    return allocate_section_contents(plt, dynobj, plt->size);
}

static bool
_bfinfdpic_size_got_plt(bfd *output_bfd, struct _bfinfdpic_dynamic_got_plt_info *gpinfop)
{
    struct bfd_link_info *info = gpinfop->g.info;
    bfd *dynobj = elf_hash_table(info)->dynobj;
    
    memcpy(bfinfdpic_dynamic_got_plt_info(info), &gpinfop->g, sizeof(gpinfop->g));
    
    bfd_vma limit = calculate_limit_for_18bit_range(gpinfop, INITIAL_ODD_OFFSET);
    bfd_signed_vma odd = compute_got_allocations(gpinfop, limit);
    
    htab_traverse(bfinfdpic_relocs_info(info), _bfinfdpic_assign_got_entries, gpinfop);
    
    if (!setup_got_section(info, gpinfop, odd, dynobj))
        return false;
    
    if (!setup_gotrel_section(info, gpinfop, dynobj, output_bfd))
        return false;
    
    if (!setup_gotfixup_section(info, gpinfop, dynobj))
        return false;
    
    if (!setup_pltrel_section(info, gpinfop, dynobj, output_bfd))
        return false;
    
    calculate_plt_section_size(info, gpinfop);
    
    gpinfop->g.lzplt = 0;
    
    setup_got_and_plt_offsets(info, gpinfop, output_bfd);
    
    htab_traverse(bfinfdpic_relocs_info(info), _bfinfdpic_assign_plt_entries, gpinfop);
    
    if (!allocate_plt_section(info, dynobj))
        return false;
    
    return true;
}

/* Set the sizes of the dynamic sections.  */

static bool
set_interp_section(bfd *dynobj, struct bfd_link_info *info)
{
  asection *s;
  
  if (!bfd_link_executable(info) || info->nointerp)
    return true;
    
  s = bfd_get_linker_section(dynobj, ".interp");
  BFD_ASSERT(s != NULL);
  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
  s->contents = (bfd_byte *) ELF_DYNAMIC_INTERPRETER;
  s->alloced = 1;
  
  return true;
}

static void
resolve_final_relocs(struct bfd_link_info *info)
{
  htab_t relocs;
  
  for (;;)
    {
      relocs = bfinfdpic_relocs_info(info);
      htab_traverse(relocs, _bfinfdpic_resolve_final_relocs_info, &relocs);
      
      if (relocs == bfinfdpic_relocs_info(info))
        break;
    }
}

static void
exclude_empty_section(bfd *dynobj, const char *section_name)
{
  asection *s = bfd_get_linker_section(dynobj, section_name);
  if (s && s->size == 0)
    s->flags |= SEC_EXCLUDE;
}

static bool
elf32_bfinfdpic_late_size_sections(bfd *output_bfd,
                                   struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab;
  bfd *dynobj;
  struct _bfinfdpic_dynamic_got_plt_info gpinfo;

  htab = elf_hash_table(info);
  dynobj = htab->dynobj;
  if (dynobj == NULL)
    return true;

  if (htab->dynamic_sections_created)
    set_interp_section(dynobj, info);

  memset(&gpinfo, 0, sizeof(gpinfo));
  gpinfo.g.info = info;

  resolve_final_relocs(info);

  htab_traverse(bfinfdpic_relocs_info(info), _bfinfdpic_count_got_plt_entries,
                &gpinfo.g);

  bfinfdpic_dynamic_got_plt_info(info) = bfd_alloc(dynobj, sizeof(gpinfo.g));

  if (!_bfinfdpic_size_got_plt(output_bfd, &gpinfo))
    return false;

  exclude_empty_section(dynobj, ".dynbss");
  exclude_empty_section(dynobj, ".rela.bss");

  return _bfd_elf_add_dynamic_tags(output_bfd, info, true);
}

static bool
elf32_bfinfdpic_early_size_sections (bfd *output_bfd,
				     struct bfd_link_info *info)
{
  if (!bfd_link_relocatable (info)
      && !bfd_elf_stack_segment_size (output_bfd, info,
				      "__stacksize", DEFAULT_STACK_SIZE))
    return false;

  return true;
}

/* Check whether any of the relocations was optimized away, and
   subtract it from the relocation or fixup count.  */
static bool
is_relevant_relocation(unsigned int r_type)
{
  return r_type == R_BFIN_BYTE4_DATA || r_type == R_BFIN_FUNCDESC;
}

static bool
is_offset_discarded(bfd *output_owner, struct bfd_link_info *info, 
                   asection *sec, bfd_vma r_offset)
{
  return _bfd_elf_section_offset(output_owner, info, sec, r_offset) == (bfd_vma)-1;
}

static struct elf_link_hash_entry *
resolve_hash_entry(struct elf_link_hash_entry *h)
{
  while (h->root.type == bfd_link_hash_indirect || 
         h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *)h->root.u.i.link;
  return h;
}

static struct elf_link_hash_entry *
get_hash_entry(unsigned long r_symndx, Elf_Internal_Shdr *symtab_hdr,
              struct elf_link_hash_entry **sym_hashes)
{
  if (r_symndx < symtab_hdr->sh_info)
    return NULL;
  
  struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  return resolve_hash_entry(h);
}

static struct bfinfdpic_relocs_info *
get_picrel_info(struct bfd_link_info *info, bfd *abfd,
               struct elf_link_hash_entry *h, unsigned long r_symndx,
               bfd_vma r_addend)
{
  if (h != NULL)
    return bfinfdpic_relocs_info_for_global(bfinfdpic_relocs_info(info),
                                           abfd, h, r_addend, NO_INSERT);
  else
    return bfinfdpic_relocs_info_for_local(bfinfdpic_relocs_info(info),
                                          abfd, r_symndx, r_addend, NO_INSERT);
}

static void
update_relocation_counts(struct bfinfdpic_relocs_info *picrel,
                        struct _bfinfdpic_dynamic_got_info *dinfo,
                        unsigned int r_type)
{
  _bfinfdpic_count_relocs_fixups(picrel, dinfo, true);
  
  if (r_type == R_BFIN_BYTE4_DATA)
    picrel->relocs32--;
  else
    picrel->relocsfd--;
  
  _bfinfdpic_count_relocs_fixups(picrel, dinfo, false);
}

static bool
process_single_relocation(Elf_Internal_Rela *rel, bfd *abfd, asection *sec,
                         struct bfd_link_info *info, Elf_Internal_Shdr *symtab_hdr,
                         struct elf_link_hash_entry **sym_hashes, bool *changed)
{
  unsigned int r_type = ELF32_R_TYPE(rel->r_info);
  
  if (!is_relevant_relocation(r_type))
    return true;
  
  if (!is_offset_discarded(sec->output_section->owner, info, sec, rel->r_offset))
    return true;
  
  unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
  struct elf_link_hash_entry *h = get_hash_entry(r_symndx, symtab_hdr, sym_hashes);
  
  struct bfinfdpic_relocs_info *picrel = get_picrel_info(info, abfd, h, 
                                                         r_symndx, rel->r_addend);
  if (!picrel)
    return false;
  
  *changed = true;
  struct _bfinfdpic_dynamic_got_info *dinfo = bfinfdpic_dynamic_got_plt_info(info);
  update_relocation_counts(picrel, dinfo, r_type);
  
  return true;
}

static bool
_bfinfdpic_check_discarded_relocs(bfd *abfd, asection *sec,
                                 struct bfd_link_info *info,
                                 bool *changed)
{
  if ((sec->flags & SEC_RELOC) == 0 || sec->reloc_count == 0)
    return true;
  
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
  Elf_Internal_Rela *rel = elf_section_data(sec)->relocs;
  Elf_Internal_Rela *erel = rel + sec->reloc_count;
  
  for (; rel < erel; rel++)
    {
      if (!process_single_relocation(rel, abfd, sec, info, symtab_hdr, 
                                    sym_hashes, changed))
        return false;
    }
  
  return true;
}

static bool
process_eh_frame_sections(bfd *ibfd, struct bfd_link_info *info, bool *changed, bfd **obfd)
{
    asection *s;
    for (s = ibfd->sections; s; s = s->next)
    {
        if (s->sec_info_type != SEC_INFO_TYPE_EH_FRAME)
            continue;
        
        if (!_bfinfdpic_check_discarded_relocs(ibfd, s, info, changed))
            return false;
        
        *obfd = s->output_section->owner;
    }
    return true;
}

static bool
update_got_plt_info(bfd *obfd, struct bfd_link_info *info)
{
    struct _bfinfdpic_dynamic_got_plt_info gpinfo;
    
    memset(&gpinfo, 0, sizeof(gpinfo));
    memcpy(&gpinfo.g, bfinfdpic_dynamic_got_plt_info(info), sizeof(gpinfo.g));
    
    htab_traverse(bfinfdpic_relocs_info(info), _bfinfdpic_reset_got_plt_entries, NULL);
    
    return _bfinfdpic_size_got_plt(obfd, &gpinfo);
}

static bool
bfinfdpic_elf_discard_info(bfd *ibfd,
                          struct elf_reloc_cookie *cookie ATTRIBUTE_UNUSED,
                          struct bfd_link_info *info)
{
    bool changed = false;
    bfd *obfd = NULL;
    
    if (!process_eh_frame_sections(ibfd, info, &changed, &obfd))
        return false;
    
    if (changed && !update_got_plt_info(obfd, info))
        return false;
    
    return true;
}

static bool
validate_gotrel_section_size(struct bfd_link_info *info)
{
    return bfinfdpic_gotrel_section(info)->size >= 
           (bfinfdpic_gotrel_section(info)->reloc_count * sizeof(Elf32_External_Rel));
}

static bool
validate_gotfixup_section_size(struct bfd_link_info *info)
{
    #define FIXUP_ENTRY_SIZE 4
    
    if (bfinfdpic_gotfixup_section(info)->size != 
        (bfinfdpic_gotfixup_section(info)->reloc_count * FIXUP_ENTRY_SIZE))
    {
        _bfd_error_handler("LINKER BUG: .rofixup section size mismatch");
        return false;
    }
    return true;
}

static bfd_vma
calculate_got_value(struct elf_link_hash_entry *hgot)
{
    return hgot->root.u.def.value +
           hgot->root.u.def.section->output_section->vma +
           hgot->root.u.def.section->output_offset;
}

static bool
process_gotfixup_section(bfd *output_bfd, struct bfd_link_info *info)
{
    if (!bfinfdpic_gotfixup_section(info))
        return true;
        
    struct elf_link_hash_entry *hgot = elf_hash_table(info)->hgot;
    bfd_vma got_value = calculate_got_value(hgot);
    
    _bfinfdpic_add_rofixup(output_bfd, bfinfdpic_gotfixup_section(info), got_value, 0);
    
    return validate_gotfixup_section_size(info);
}

static bool
process_got_sections(bfd *output_bfd, struct bfd_link_info *info)
{
    if (!bfinfdpic_got_section(info))
        return true;
        
    BFD_ASSERT(validate_gotrel_section_size(info));
    
    return process_gotfixup_section(output_bfd, info);
}

static void
validate_pltrel_section(struct bfd_link_info *info)
{
    BFD_ASSERT(bfinfdpic_pltrel_section(info)->size ==
               (bfinfdpic_pltrel_section(info)->reloc_count * sizeof(Elf32_External_Rel)));
}

static bfd_vma
calculate_section_output_address(asection *section)
{
    return section->output_section->vma + section->output_offset;
}

static void
update_dyn_pltgot(bfd *output_bfd, Elf_Internal_Dyn *dyn, 
                  Elf32_External_Dyn *dyncon, struct bfd_link_info *info)
{
    dyn->d_un.d_ptr = calculate_section_output_address(bfinfdpic_got_section(info)) +
                      bfinfdpic_got_initial_offset(info);
    bfd_elf32_swap_dyn_out(output_bfd, dyn, dyncon);
}

static void
update_dyn_jmprel(bfd *output_bfd, Elf_Internal_Dyn *dyn,
                  Elf32_External_Dyn *dyncon, struct bfd_link_info *info)
{
    dyn->d_un.d_ptr = calculate_section_output_address(bfinfdpic_pltrel_section(info));
    bfd_elf32_swap_dyn_out(output_bfd, dyn, dyncon);
}

static void
update_dyn_pltrelsz(bfd *output_bfd, Elf_Internal_Dyn *dyn,
                    Elf32_External_Dyn *dyncon, struct bfd_link_info *info)
{
    dyn->d_un.d_val = bfinfdpic_pltrel_section(info)->size;
    bfd_elf32_swap_dyn_out(output_bfd, dyn, dyncon);
}

static void
process_dynamic_entry(bfd *output_bfd, bfd *dynobj, Elf32_External_Dyn *dyncon,
                      struct bfd_link_info *info)
{
    Elf_Internal_Dyn dyn;
    bfd_elf32_swap_dyn_in(dynobj, dyncon, &dyn);
    
    switch (dyn.d_tag)
    {
    case DT_PLTGOT:
        update_dyn_pltgot(output_bfd, &dyn, dyncon, info);
        break;
    case DT_JMPREL:
        update_dyn_jmprel(output_bfd, &dyn, dyncon, info);
        break;
    case DT_PLTRELSZ:
        update_dyn_pltrelsz(output_bfd, &dyn, dyncon, info);
        break;
    default:
        break;
    }
}

static void
process_dynamic_section(bfd *output_bfd, bfd *dynobj, asection *sdyn,
                        struct bfd_link_info *info)
{
    BFD_ASSERT(sdyn != NULL);
    
    Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *)sdyn->contents;
    Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);
    
    for (; dyncon < dynconend; dyncon++)
    {
        process_dynamic_entry(output_bfd, dynobj, dyncon, info);
    }
}

static bool
elf32_bfinfdpic_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info)
{
    bfd *dynobj = elf_hash_table(info)->dynobj;
    
    if (!process_got_sections(output_bfd, info))
        return false;
    
    if (elf_hash_table(info)->dynamic_sections_created)
    {
        validate_pltrel_section(info);
        
        asection *sdyn = bfd_get_linker_section(dynobj, ".dynamic");
        process_dynamic_section(output_bfd, dynobj, sdyn, info);
    }
    
    return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  */

static bool
elf32_bfinfdpic_adjust_dynamic_symbol (struct bfd_link_info *info,
				       struct elf_link_hash_entry *h)
{
  bfd * dynobj;

  dynobj = elf_hash_table (info)->dynobj;

  BFD_ASSERT (dynobj != NULL
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
  struct elf_link_hash_entry *h;
  struct elf_link_hash_entry *got_entry;
  asection *got_output_section;
  bfd_vma got_value;

  h = elf_hash_table (info)->hgot;
  BFD_ASSERT (h && h->root.type == bfd_link_hash_defined);

  if (!h)
    return _bfd_elf_encode_eh_address (abfd, info, osec, offset,
                                      loc_sec, loc_offset, encoded);

  if (_bfinfdpic_osec_to_segment (abfd, osec) ==
      _bfinfdpic_osec_to_segment (abfd, loc_sec->output_section))
    return _bfd_elf_encode_eh_address (abfd, info, osec, offset,
                                      loc_sec, loc_offset, encoded);

  got_entry = h;
  got_output_section = got_entry->root.u.def.section->output_section;
  
  BFD_ASSERT (_bfinfdpic_osec_to_segment (abfd, osec) ==
              _bfinfdpic_osec_to_segment (abfd, got_output_section));

  got_value = got_entry->root.u.def.value +
              got_output_section->vma +
              got_entry->root.u.def.section->output_offset;

  *encoded = osec->vma + offset - got_value;

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

static struct elf_link_hash_entry *
resolve_indirect_hash(struct elf_link_hash_entry *h)
{
  while (h->root.type == bfd_link_hash_indirect ||
         h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  return h;
}

static struct elf_link_hash_entry *
get_hash_entry(Elf_Internal_Shdr *symtab_hdr,
               struct elf_link_hash_entry **sym_hashes,
               unsigned long r_symndx)
{
  if (r_symndx < symtab_hdr->sh_info)
    return NULL;
  return resolve_indirect_hash(sym_hashes[r_symndx - symtab_hdr->sh_info]);
}

static bool
ensure_dynobj_exists(bfd *abfd, struct bfd_link_info *info)
{
  if (!elf_hash_table(info)->dynobj)
  {
    elf_hash_table(info)->dynobj = abfd;
    if (!_bfin_create_got_section(abfd, info))
      return false;
  }
  return true;
}

static void
record_dynamic_symbol_if_needed(struct bfd_link_info *info,
                                struct elf_link_hash_entry *h)
{
  if (h->dynindx == -1)
  {
    switch (ELF_ST_VISIBILITY(h->other))
    {
    case STV_INTERNAL:
    case STV_HIDDEN:
      break;
    default:
      bfd_elf_link_record_dynamic_symbol(info, h);
      break;
    }
  }
}

static struct bfinfdpic_relocs_info *
get_picrel_info(struct bfd_link_info *info, bfd *abfd,
                struct elf_link_hash_entry *h,
                unsigned long r_symndx, bfd_vma r_addend)
{
  if (h != NULL)
  {
    record_dynamic_symbol_if_needed(info, h);
    return bfinfdpic_relocs_info_for_global(bfinfdpic_relocs_info(info),
                                           abfd, h, r_addend, INSERT);
  }
  return bfinfdpic_relocs_info_for_local(bfinfdpic_relocs_info(info),
                                        abfd, r_symndx, r_addend, INSERT);
}

static bool
is_fdpic_specific_reloc(unsigned int r_type)
{
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
    return true;
  default:
    return false;
  }
}

static bool
needs_picrel_info(unsigned int r_type)
{
  switch (r_type)
  {
  case R_BFIN_PCREL24:
  case R_BFIN_PCREL24_JUMP_L:
  case R_BFIN_BYTE4_DATA:
    return true;
  default:
    return is_fdpic_specific_reloc(r_type);
  }
}

static void
update_picrel_call_counts(struct bfinfdpic_relocs_info *picrel,
                          unsigned int r_type)
{
  switch (r_type)
  {
  case R_BFIN_PCREL24:
  case R_BFIN_PCREL24_JUMP_L:
    picrel->call++;
    break;
  }
}

static void
update_picrel_data_counts(struct bfinfdpic_relocs_info *picrel,
                          unsigned int r_type, asection *sec)
{
  bool is_alloc = bfd_section_flags(sec) & SEC_ALLOC;
  
  switch (r_type)
  {
  case R_BFIN_FUNCDESC_VALUE:
    picrel->relocsfdv++;
    if (is_alloc)
      picrel->relocs32--;
    picrel->sym++;
    if (is_alloc)
      picrel->relocs32++;
    break;
  case R_BFIN_BYTE4_DATA:
    picrel->sym++;
    if (is_alloc)
      picrel->relocs32++;
    break;
  }
}

static void
update_picrel_got_counts(struct bfinfdpic_relocs_info *picrel,
                         unsigned int r_type)
{
  switch (r_type)
  {
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
  }
}

static bool
handle_vtable_relocs(bfd *abfd, asection *sec,
                    struct elf_link_hash_entry *h,
                    const Elf_Internal_Rela *rel)
{
  unsigned int r_type = ELF32_R_TYPE(rel->r_info);
  
  switch (r_type)
  {
  case R_BFIN_GNU_VTINHERIT:
    return bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset);
  case R_BFIN_GNU_VTENTRY:
    BFD_ASSERT(h != NULL);
    if (h != NULL)
      return bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend);
    break;
  }
  return true;
}

static bool
is_supported_reloc(unsigned int r_type)
{
  switch (r_type)
  {
  case R_BFIN_HUIMM16:
  case R_BFIN_LUIMM16:
  case R_BFIN_PCREL12_JUMP_S:
  case R_BFIN_PCREL10:
  case R_BFIN_GNU_VTINHERIT:
  case R_BFIN_GNU_VTENTRY:
    return true;
  default:
    return needs_picrel_info(r_type);
  }
}

static bool
process_single_reloc(bfd *abfd, struct bfd_link_info *info,
                    asection *sec, const Elf_Internal_Rela *rel,
                    Elf_Internal_Shdr *symtab_hdr,
                    struct elf_link_hash_entry **sym_hashes)
{
  unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
  unsigned int r_type = ELF32_R_TYPE(rel->r_info);
  struct elf_link_hash_entry *h;
  struct bfinfdpic_relocs_info *picrel = NULL;
  
  h = get_hash_entry(symtab_hdr, sym_hashes, r_symndx);
  
  if (is_fdpic_specific_reloc(r_type) && !IS_FDPIC(abfd))
  {
    _bfd_error_handler(_("%pB: unsupported relocation type %#x"),
                      abfd, r_type);
    return false;
  }
  
  if (needs_picrel_info(r_type) && IS_FDPIC(abfd))
  {
    if (!ensure_dynobj_exists(abfd, info))
      return false;
    
    picrel = get_picrel_info(info, abfd, h, r_symndx, rel->r_addend);
    if (!picrel)
      return false;
      
    update_picrel_call_counts(picrel, r_type);
    update_picrel_data_counts(picrel, r_type, sec);
    update_picrel_got_counts(picrel, r_type);
  }
  
  if (!handle_vtable_relocs(abfd, sec, h, rel))
    return false;
  
  if (!is_supported_reloc(r_type))
  {
    _bfd_error_handler(_("%pB: unsupported relocation type %#x"),
                      abfd, r_type);
    return false;
  }
  
  return true;
}

static bool
bfinfdpic_check_relocs(bfd *abfd, struct bfd_link_info *info,
                      asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  
  if (bfd_link_relocatable(info))
    return true;
  
  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes(abfd);
  
  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
  {
    if (!process_single_reloc(abfd, info, sec, rel, symtab_hdr, sym_hashes))
      return false;
  }
  
  return true;
}

/* Set the right machine number for a Blackfin ELF file.  */

static bool
elf32_bfin_object_p (bfd *abfd)
{
  bfd_default_set_arch_mach (abfd, bfd_arch_bfin, 0);
  
  bool has_fdpic_flag = (elf_elfheader (abfd)->e_flags & EF_BFIN_FDPIC) != 0;
  bool is_fdpic = IS_FDPIC (abfd);
  
  return has_fdpic_flag == is_fdpic;
}

static bool
elf32_bfin_set_private_flags (bfd * abfd, flagword flags)
{
  elf_elfheader (abfd)->e_flags = flags;
  elf_flags_init (abfd) = true;
  return true;
}

/* Display the flags field.  */
static bool
elf32_bfin_print_private_bfd_data (bfd * abfd, void * ptr)
{
  FILE *file = (FILE *) ptr;
  flagword flags;

  BFD_ASSERT (abfd != NULL && ptr != NULL);

  _bfd_elf_print_private_bfd_data (abfd, ptr);

  flags = elf_elfheader (abfd)->e_flags;

  fprintf (file, _("private flags = %lx:"), flags);

  if (flags & EF_BFIN_PIC)
    fprintf (file, " -fpic");

  if (flags & EF_BFIN_FDPIC)
    fprintf (file, " -mfdpic");

  fputc ('\n', file);

  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
is_dynamic_object(bfd *ibfd)
{
    return (ibfd->flags & DYNAMIC) != 0;
}

static flagword
get_adjusted_flags(flagword flags)
{
    if (flags & EF_BFIN_FDPIC)
        return flags & ~EF_BFIN_PIC;
    return flags;
}

static void
log_merge_flags(flagword old_flags, flagword new_flags, bfd *obfd, bfd *ibfd)
{
#ifndef DEBUG
    if (0)
#endif
    _bfd_error_handler
        ("old_flags = 0x%.8x, new_flags = 0x%.8x, init = %s, filename = %pB",
         old_flags, new_flags, elf_flags_init(obfd) ? "yes" : "no", ibfd);
}

static void
initialize_output_flags(bfd *obfd, flagword new_flags)
{
    if (!elf_flags_init(obfd))
    {
        elf_flags_init(obfd) = true;
        elf_elfheader(obfd)->e_flags = new_flags;
    }
}

static bool
check_fdpic_compatibility(flagword new_flags, bfd *obfd, bfd *ibfd)
{
    bool new_is_non_fdpic = (new_flags & EF_BFIN_FDPIC) == 0;
    bool obfd_is_fdpic = IS_FDPIC(obfd);
    
    if (new_is_non_fdpic != !obfd_is_fdpic)
    {
        if (obfd_is_fdpic)
            _bfd_error_handler
                (_("%pB: cannot link non-fdpic object file into fdpic executable"),
                 ibfd);
        else
            _bfd_error_handler
                (_("%pB: cannot link fdpic object file into non-fdpic executable"),
                 ibfd);
        return false;
    }
    return true;
}

static bool
elf32_bfin_merge_private_bfd_data(bfd *ibfd, struct bfd_link_info *info)
{
    bfd *obfd = info->output_bfd;
    flagword old_flags, new_flags;
    bool error = false;

    if (is_dynamic_object(ibfd))
        return true;

    new_flags = get_adjusted_flags(elf_elfheader(ibfd)->e_flags);
    old_flags = elf_elfheader(obfd)->e_flags;

    log_merge_flags(old_flags, new_flags, obfd, ibfd);
    initialize_output_flags(obfd, new_flags);

    if (!check_fdpic_compatibility(new_flags, obfd, ibfd))
    {
        error = true;
        bfd_set_error(bfd_error_bad_value);
    }

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
allocate_hash_entry_if_needed(struct bfd_hash_entry *entry,
                              struct bfd_hash_table *table)
{
  if (entry != NULL)
    return entry;
  
  return bfd_hash_allocate(table, sizeof(struct bfin_link_hash_entry));
}

static struct bfd_hash_entry *
initialize_bfin_hash_entry(struct bfd_hash_entry *entry,
                          struct bfd_hash_table *table,
                          const char *string)
{
  struct bfd_hash_entry *ret = _bfd_elf_link_hash_newfunc(entry, table, string);
  
  if (ret != NULL)
    bfin_hash_entry(ret)->pcrel_relocs_copied = NULL;
  
  return ret;
}

static struct bfd_hash_entry *
bfin_link_hash_newfunc(struct bfd_hash_entry *entry,
                      struct bfd_hash_table *table,
                      const char *string)
{
  struct bfd_hash_entry *ret = allocate_hash_entry_if_needed(entry, table);
  
  if (ret == NULL)
    return NULL;
  
  return initialize_bfin_hash_entry(ret, table, string);
}

/* Create an bfin ELF linker hash table.  */

static struct bfd_link_hash_table *
bfin_link_hash_table_create (bfd * abfd)
{
  struct elf_link_hash_table *ret;
  size_t amt = sizeof (struct elf_link_hash_table);

  ret = bfd_zmalloc (amt);
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
  bfd *dynobj;
  asection *sdyn;

  dynobj = elf_hash_table (info)->dynobj;
  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (!elf_hash_table (info)->dynamic_sections_created)
    {
      return true;
    }

  BFD_ASSERT (sdyn != NULL);

  Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *) sdyn->contents;
  Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
  
  for (; dyncon < dynconend; dyncon++)
    {
      Elf_Internal_Dyn dyn;
      bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);
    }

  return true;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
is_symbolic_local_reloc(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  return bfd_link_pic(info) &&
         (info->symbolic || h->dynindx == -1 || h->forced_local) &&
         h->def_regular;
}

static bfd_vma
get_got_offset_mask(struct elf_link_hash_entry *h)
{
  return h->got.offset & ~(bfd_vma)1;
}

static void
setup_symbolic_reloc(bfd *output_bfd, asection *sgot, 
                    struct elf_link_hash_entry *h, Elf_Internal_Rela *rela)
{
  _bfd_error_handler(_("*** check this relocation %s"), __func__);
  rela->r_info = ELF32_R_INFO(0, R_BFIN_PCREL24);
  rela->r_addend = bfd_get_signed_32(output_bfd,
                                     sgot->contents + get_got_offset_mask(h));
}

static void
setup_standard_reloc(bfd *output_bfd, asection *sgot,
                    struct elf_link_hash_entry *h, Elf_Internal_Rela *rela)
{
  bfd_put_32(output_bfd, (bfd_vma)0,
             sgot->contents + get_got_offset_mask(h));
  rela->r_info = ELF32_R_INFO(h->dynindx, R_BFIN_GOT);
  rela->r_addend = 0;
}

static void
write_reloc_entry(bfd *output_bfd, asection *srela, Elf_Internal_Rela *rela)
{
  bfd_byte *loc = srela->contents + srela->reloc_count * sizeof(Elf32_External_Rela);
  srela->reloc_count++;
  bfd_elf32_swap_reloca_out(output_bfd, rela, loc);
}

static void
process_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                 struct elf_link_hash_entry *h)
{
  asection *sgot;
  asection *srela;
  Elf_Internal_Rela rela;

  sgot = elf_hash_table(info)->sgot;
  srela = elf_hash_table(info)->srelgot;
  BFD_ASSERT(sgot != NULL && srela != NULL);

  rela.r_offset = sgot->output_section->vma +
                  sgot->output_offset +
                  get_got_offset_mask(h);

  if (is_symbolic_local_reloc(info, h))
    setup_symbolic_reloc(output_bfd, sgot, h, &rela);
  else
    setup_standard_reloc(output_bfd, sgot, h, &rela);

  write_reloc_entry(output_bfd, srela, &rela);
}

static bool
bfin_finish_dynamic_symbol(bfd *output_bfd,
                          struct bfd_link_info *info,
                          struct elf_link_hash_entry *h,
                          Elf_Internal_Sym *sym)
{
  if (h->got.offset != (bfd_vma)-1)
    process_got_entry(output_bfd, info, h);

  if (h->needs_copy)
    BFD_ASSERT(0);

  if (strcmp(h->root.root.string, "__DYNAMIC") == 0 ||
      h == elf_hash_table(info)->hgot)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool handle_weak_alias(struct elf_link_hash_entry *h)
{
    struct elf_link_hash_entry *def = weakdef(h);
    BFD_ASSERT(def->root.type == bfd_link_hash_defined);
    h->root.u.def.section = def->root.u.def.section;
    h->root.u.def.value = def->root.u.def.value;
    return true;
}

static bool check_copy_reloc_support(struct elf_link_hash_entry *h)
{
    if ((h->root.u.def.section->flags & SEC_ALLOC) != 0)
    {
        _bfd_error_handler(_("the bfin target does not currently support the generation of copy relocations"));
        return false;
    }
    return true;
}

static unsigned int calculate_alignment_power(bfd_vma size)
{
    unsigned int power_of_two = bfd_log2(size);
    const unsigned int MAX_ALIGNMENT_POWER = 3;
    if (power_of_two > MAX_ALIGNMENT_POWER)
        power_of_two = MAX_ALIGNMENT_POWER;
    return power_of_two;
}

static bool align_and_allocate_symbol(asection *s, struct elf_link_hash_entry *h)
{
    unsigned int power_of_two = calculate_alignment_power(h->size);
    
    s->size = BFD_ALIGN(s->size, (bfd_size_type)(1 << power_of_two));
    if (!bfd_link_align_section(s, power_of_two))
        return false;
    
    h->root.u.def.section = s;
    h->root.u.def.value = s->size;
    s->size += h->size;
    
    return true;
}

static bool
bfin_adjust_dynamic_symbol(struct bfd_link_info *info,
                          struct elf_link_hash_entry *h)
{
    bfd *dynobj;
    asection *s;
    
    dynobj = elf_hash_table(info)->dynobj;
    
    BFD_ASSERT(dynobj != NULL
              && (h->needs_plt
                  || h->is_weakalias
                  || (h->def_dynamic && h->ref_regular && !h->def_regular)));
    
    if (h->type == STT_FUNC || h->needs_plt)
    {
        BFD_ASSERT(0);
    }
    
    if (h->is_weakalias)
    {
        return handle_weak_alias(h);
    }
    
    if (bfd_link_pic(info))
        return true;
    
    s = bfd_get_linker_section(dynobj, ".dynbss");
    BFD_ASSERT(s != NULL);
    
    if (!check_copy_reloc_support(h))
        return false;
    
    return align_and_allocate_symbol(s, h);
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

static bool should_process_relocations(struct elf_link_hash_entry *h, struct bfd_link_info *info)
{
    return !h->def_regular || (!info->symbolic && !h->forced_local);
}

static void check_readonly_sections(struct bfd_link_info *info, struct bfin_pcrel_relocs_copied *relocs)
{
    if ((info->flags & DF_TEXTREL) != 0)
        return;
    
    for (struct bfin_pcrel_relocs_copied *s = relocs; s != NULL; s = s->next)
    {
        if ((s->section->flags & SEC_READONLY) != 0)
        {
            info->flags |= DF_TEXTREL;
            break;
        }
    }
}

static void adjust_section_sizes(struct bfin_pcrel_relocs_copied *relocs)
{
    for (struct bfin_pcrel_relocs_copied *s = relocs; s != NULL; s = s->next)
    {
        s->section->size -= s->count * sizeof (Elf32_External_Rela);
    }
}

static bool
bfin_discard_copies (struct elf_link_hash_entry *h, void * inf)
{
    struct bfd_link_info *info = (struct bfd_link_info *) inf;
    struct bfin_pcrel_relocs_copied *relocs = bfin_hash_entry (h)->pcrel_relocs_copied;
    
    if (should_process_relocations(h, info))
    {
        check_readonly_sections(info, relocs);
        return true;
    }
    
    adjust_section_sizes(relocs);
    return true;
}

static bool
set_interp_section(bfd *dynobj, struct bfd_link_info *info)
{
  asection *s;
  
  if (!bfd_link_executable(info) || info->nointerp)
    return true;
    
  s = bfd_get_linker_section(dynobj, ".interp");
  BFD_ASSERT(s != NULL);
  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
  s->alloced = 1;
  
  return true;
}

static void
reset_relgot_section(struct bfd_link_info *info)
{
  asection *s = elf_hash_table(info)->srelgot;
  if (s != NULL)
    s->size = 0;
}

static bool
should_strip_section(asection *s, const char *name)
{
  if (startswith(name, ".rela"))
    return s->size == 0;
  return false;
}

static bool
allocate_section_contents(bfd *dynobj, asection *s)
{
  s->contents = (bfd_byte *) bfd_zalloc(dynobj, s->size);
  if (s->contents == NULL && s->size != 0)
    return false;
  s->alloced = 1;
  return true;
}

static bool
process_dynamic_section(bfd *dynobj, asection *s, bool *relocs)
{
  const char *name;
  bool strip;
  
  if ((s->flags & SEC_LINKER_CREATED) == 0)
    return true;
    
  name = bfd_section_name(s);
  strip = should_strip_section(s, name);
  
  if (startswith(name, ".rela") && !strip)
  {
    *relocs = true;
    s->reloc_count = 0;
  }
  else if (!startswith(name, ".got"))
  {
    return true;
  }
  
  if (strip)
  {
    s->flags |= SEC_EXCLUDE;
    return true;
  }
  
  return allocate_section_contents(dynobj, s);
}

static bool
add_dynamic_entries(struct bfd_link_info *info, bool relocs)
{
  #define add_dynamic_entry(TAG, VAL) \
    _bfd_elf_add_dynamic_entry(info, TAG, VAL)
  
  if (!bfd_link_pic(info))
  {
    if (!add_dynamic_entry(DT_DEBUG, 0))
      return false;
  }
  
  if (relocs)
  {
    if (!add_dynamic_entry(DT_RELA, 0) ||
        !add_dynamic_entry(DT_RELASZ, 0) ||
        !add_dynamic_entry(DT_RELAENT, sizeof(Elf32_External_Rela)))
      return false;
  }
  
  if ((info->flags & DF_TEXTREL) != 0)
  {
    if (!add_dynamic_entry(DT_TEXTREL, 0))
      return false;
  }
  
  #undef add_dynamic_entry
  return true;
}

static bool
bfin_late_size_sections(bfd *output_bfd ATTRIBUTE_UNUSED,
                       struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *s;
  bool relocs = false;
  
  dynobj = elf_hash_table(info)->dynobj;
  if (dynobj == NULL)
    return true;
  
  if (elf_hash_table(info)->dynamic_sections_created)
  {
    if (!set_interp_section(dynobj, info))
      return false;
  }
  else
  {
    reset_relgot_section(info);
  }
  
  if (bfd_link_pic(info))
    elf_link_hash_traverse(elf_hash_table(info), bfin_discard_copies, info);
  
  for (s = dynobj->sections; s != NULL; s = s->next)
  {
    if (!process_dynamic_section(dynobj, s, &relocs))
      return false;
  }
  
  if (elf_hash_table(info)->dynamic_sections_created)
  {
    if (!add_dynamic_entries(info, relocs))
      return false;
  }
  
  return true;
}

/* Given a .data section and a .emreloc in-memory section, store
   relocation information into the .emreloc section which can be
   used at runtime to relocate the section.  This is called by the
   linker when the --embedded-relocs switch is used.  This is called
   after the add_symbols entry point has been called for all the
   objects, and before the final_link entry point is called.  */

#define RELOC_ENTRY_SIZE 12
#define TARGET_NAME_SIZE 8
#define TARGET_NAME_OFFSET 4

static void free_resources(Elf_Internal_Shdr *symtab_hdr,
                          Elf_Internal_Sym *isymbuf,
                          asection *datasec,
                          Elf_Internal_Rela *internal_relocs)
{
    if (symtab_hdr->contents != (unsigned char *) isymbuf)
        free(isymbuf);
    if (elf_section_data(datasec)->relocs != internal_relocs)
        free(internal_relocs);
}

static bool validate_relocation_type(Elf_Internal_Rela *irel, char **errmsg)
{
    if (ELF32_R_TYPE(irel->r_info) != (int) R_BFIN_BYTE4_DATA) {
        *errmsg = _("unsupported relocation type");
        bfd_set_error(bfd_error_bad_value);
        return false;
    }
    return true;
}

static Elf_Internal_Sym* load_local_symbols(bfd *abfd, 
                                           Elf_Internal_Shdr *symtab_hdr)
{
    Elf_Internal_Sym *isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
    if (isymbuf == NULL) {
        isymbuf = bfd_elf_get_elf_syms(abfd, symtab_hdr,
                                      symtab_hdr->sh_info, 0,
                                      NULL, NULL, NULL);
    }
    return isymbuf;
}

static asection* get_local_target_section(bfd *abfd,
                                         Elf_Internal_Shdr *symtab_hdr,
                                         Elf_Internal_Rela *irel,
                                         Elf_Internal_Sym **isymbuf)
{
    if (*isymbuf == NULL) {
        *isymbuf = load_local_symbols(abfd, symtab_hdr);
        if (*isymbuf == NULL)
            return NULL;
    }
    
    Elf_Internal_Sym *isym = *isymbuf + ELF32_R_SYM(irel->r_info);
    return bfd_section_from_elf_index(abfd, isym->st_shndx);
}

static asection* get_external_target_section(bfd *abfd,
                                            Elf_Internal_Shdr *symtab_hdr,
                                            Elf_Internal_Rela *irel)
{
    unsigned long indx = ELF32_R_SYM(irel->r_info) - symtab_hdr->sh_info;
    struct elf_link_hash_entry *h = elf_sym_hashes(abfd)[indx];
    
    BFD_ASSERT(h != NULL);
    
    if (h->root.type == bfd_link_hash_defined ||
        h->root.type == bfd_link_hash_defweak) {
        return h->root.u.def.section;
    }
    return NULL;
}

static asection* get_target_section(bfd *abfd,
                                   Elf_Internal_Shdr *symtab_hdr,
                                   Elf_Internal_Rela *irel,
                                   Elf_Internal_Sym **isymbuf)
{
    if (ELF32_R_SYM(irel->r_info) < symtab_hdr->sh_info) {
        return get_local_target_section(abfd, symtab_hdr, irel, isymbuf);
    }
    return get_external_target_section(abfd, symtab_hdr, irel);
}

static void write_reloc_entry(bfd *abfd,
                             Elf_Internal_Rela *irel,
                             asection *datasec,
                             asection *targetsec,
                             bfd_byte *p)
{
    bfd_put_32(abfd, irel->r_offset + datasec->output_offset, p);
    memset(p + TARGET_NAME_OFFSET, 0, TARGET_NAME_SIZE);
    if (targetsec != NULL) {
        strncpy((char *) p + TARGET_NAME_OFFSET, 
                targetsec->output_section->name, 
                TARGET_NAME_SIZE);
    }
}

static bool allocate_reloc_section(bfd *abfd,
                                  asection *datasec,
                                  asection *relsec)
{
    bfd_size_type amt = (bfd_size_type) datasec->reloc_count * RELOC_ENTRY_SIZE;
    relsec->contents = (bfd_byte *) bfd_alloc(abfd, amt);
    if (relsec->contents == NULL)
        return false;
    relsec->alloced = 1;
    return true;
}

static bool process_relocations(bfd *abfd,
                               asection *datasec,
                               asection *relsec,
                               Elf_Internal_Shdr *symtab_hdr,
                               Elf_Internal_Rela *internal_relocs,
                               Elf_Internal_Sym **isymbuf,
                               char **errmsg)
{
    bfd_byte *p = relsec->contents;
    Elf_Internal_Rela *irelend = internal_relocs + datasec->reloc_count;
    
    for (Elf_Internal_Rela *irel = internal_relocs; irel < irelend; irel++) {
        if (!validate_relocation_type(irel, errmsg))
            return false;
        
        asection *targetsec = get_target_section(abfd, symtab_hdr, irel, isymbuf);
        if (*isymbuf == NULL && ELF32_R_SYM(irel->r_info) < symtab_hdr->sh_info)
            return false;
        
        write_reloc_entry(abfd, irel, datasec, targetsec, p);
        p += RELOC_ENTRY_SIZE;
    }
    
    return true;
}

bool bfd_bfin_elf32_create_embedded_relocs(bfd *abfd,
                                          struct bfd_link_info *info,
                                          asection *datasec,
                                          asection *relsec,
                                          char **errmsg)
{
    Elf_Internal_Sym *isymbuf = NULL;
    Elf_Internal_Rela *internal_relocs = NULL;
    
    BFD_ASSERT(!bfd_link_relocatable(info));
    *errmsg = NULL;
    
    if (datasec->reloc_count == 0)
        return true;
    
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    
    internal_relocs = _bfd_elf_link_read_relocs(abfd, datasec, NULL,
                                               (Elf_Internal_Rela *) NULL,
                                               info->keep_memory);
    if (internal_relocs == NULL)
        goto error_return;
    
    if (!allocate_reloc_section(abfd, datasec, relsec))
        goto error_return;
    
    if (!process_relocations(abfd, datasec, relsec, symtab_hdr,
                            internal_relocs, &isymbuf, errmsg))
        goto error_return;
    
    free_resources(symtab_hdr, isymbuf, datasec, internal_relocs);
    return true;
    
error_return:
    free_resources(symtab_hdr, isymbuf, datasec, internal_relocs);
    return false;
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
