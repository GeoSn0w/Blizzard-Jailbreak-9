//
//  patchfinder.c
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 7/27/22.
//  Copyright © 2022 GeoSn0w. All rights reserved.
//

#include <stdint.h>
#include <string.h>
#include "patchfinder.h"
#include <UIKit/UIKit.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t* i)
{
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t* i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t* i)
{
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t* i)
{
    if((*i & 0xF800) == 0xE000)
        return 1;
    else if((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings
static int insn_is_ldr_imm(uint16_t* i)
{
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);
    
    return opA == 6 && (opB & 4) == 4;
}

static int insn_ldr_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

// TODO: More encodings
static int insn_is_ldrb_imm(uint16_t* i)
{
    return (*i & 0xF800) == 0x7800;
}

static int insn_ldrb_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

static int insn_ldrb_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldrb_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

__unused static int insn_is_ldr_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 1;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return 1;
    else
        return 0;
}

__unused static int insn_ldr_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 3) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*i & 0xF);
    else
        return 0;
}

int insn_ldr_reg_rt(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

__unused static int insn_ldr_reg_lsl(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 0;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 4) & 0x3;
    else
        return 0;
}

static int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

__unused static int insn_is_cmp_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return 1;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return 1;
    else
        return 0;
}

__unused static int insn_cmp_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return (*i >> 8) & 7;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return *i & 0xF;
    else
        return 0;
}

__unused static int insn_cmp_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return *i & 0xFF;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else
        return 0;
}

__unused static int insn_is_and_imm(uint16_t* i)
{
    return (*i & 0xFBE0) == 0xF000 && (*(i + 1) & 0x8000) == 0;
}

__unused static int insn_and_imm_rn(uint16_t* i)
{
    return *i & 0xF;
}

__unused static int insn_and_imm_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

__unused static int insn_and_imm_imm(uint16_t* i)
{
    return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
}

static int insn_is_push(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return 1;
    else if(*i == 0xE92D)
        return 1;
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

static int insn_push_registers(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if(*i == 0xE92D)
        return *(i + 1);
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

static int insn_is_preamble_push(uint16_t* i)
{
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

static int insn_is_str_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return 1;
    else
        return 0;
}

static int insn_str_imm_postindexed(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 10) & 1;
    else
        return 0;
}

static int insn_str_imm_wback(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 0;
    else if((*i & 0xF800) == 0x9000)
        return 0;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 0;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 8) & 1;
    else
        return 0;
}

static int insn_str_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_str_imm_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_str_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if((*i & 0xF800) == 0x9000)
        return 13;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }
        
        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }
    
    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }
        
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }
    
    if(!found)
        return 0;
    
    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg)
        {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg)
        {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg)
            {
                // Can't handle this kind of operation!
                return 0;
            }
            
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address)
{
    uint16_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));
    
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_mov_imm(current_instruction))
        {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction))
        {
            int reg = insn_movt_rd(current_instruction);
            value[reg] |= insn_movt_imm(current_instruction) << 16;
            if(value[reg] == address)
            {
                return current_instruction;
            }
        } else if(insn_is_add_reg(current_instruction))
        {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg)
            {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address)
                {
                    return current_instruction;
                }
            }
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return NULL;
}

struct find_search_mask
{
    uint16_t mask;
    uint16_t value;
};

// Search the range of kdata for a series of 16-bit values that match the search mask.
static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks)
{
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur)
    {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i)
        {
            if((*(cur + i) & masks[i].mask) != masks[i].value)
            {
                matched = 0;
                break;
            }
        }
        
        if(matched)
            return cur;
    }
    
    return NULL;
}

// Helper gadget.
uint32_t find_ret0_gadget(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x00, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_ret1_gadget(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x01, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if(!pmap_map_bd)
        return 0;
    
    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t* ptr = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if(!ptr)
        return 0;
    
    // Find the beginning of it (we may have a version that throws panic after the function end).
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata) {
            return 0;
        }
        ptr--;
    }
    
    // Find the end of it.
    const uint8_t search_function_end[] = {0xF0, 0xBD};
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if(!ptr)
        return 0;
    
    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t* bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if(!bl)
        return 0;
    
    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t* ldr_r2 = NULL;
    uint16_t* current_instruction = bl;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }
        
        if(insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0)
        {
            ldr_r2 = current_instruction;
            break;
        } else if(insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction))
        {
            break;
        }
    }
    
    // The function has a third argument, which must be kernel_pmap. Find out its address
    if(ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));
    
    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the description.
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations"));
    if(!proc_enforce_description)
        return 0;
    
    // Find what references the description.
    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr)
        return 0;
    
    // Go up the struct to find the pointer to the actual data element.
    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

// Write 0 here.
uint32_t find_vnode_enforce(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the description.
    uint8_t* vnode_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on vnode operations", sizeof("Enforce MAC policy on vnode operations"));
    if(!vnode_enforce_description)
        return 0;
    
    // Find what references the description.
    uint32_t vnode_enforce_description_address = region + ((uintptr_t)vnode_enforce_description - (uintptr_t)kdata);
    uint8_t* vnode_enforce_description_ptr = memmem(kdata, ksize, &vnode_enforce_description_address, sizeof(vnode_enforce_description_address));
    if(!vnode_enforce_description_ptr)
        return 0;
    
    // Go up the struct to find the pointer to the actual data element.
    uint32_t* vnode_enforce_ptr = (uint32_t*)(vnode_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *vnode_enforce_ptr - region;
}

uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize) {
    char* amfi = memmem(kdata, ksize, "com.apple.driver.AppleMobileFileIntegrity", strlen("com.apple.driver.AppleMobileFileIntegrity"));
    uint32_t cs_enforcement_disable_amfi = (uintptr_t)amfi - (uintptr_t)kdata + 0xb1;
    printf("[*] cs_enforcement_disable_amfi: 0x%08x\n", cs_enforcement_disable_amfi);
    return cs_enforcement_disable_amfi;
}

uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x6800}, // LDR R2, [Ry,#X]
        {0xF8FF, 0x2800}, // CMP Rx, #0
        {0xFF00, 0xD100}, // BNE x
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}, // BNE x
        {0xFFF0, 0xF400}, // AND.W Rx, Ry, #0x100000
        {0xF0FF, 0x1080}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Change TST.W instruction here with NOP, CMP R0, R0 (0x4280BF00)
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04},
        {0xFF78, 0x4600}, // MOV Rx, R0 (?)
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFFF0, 0xF000}, // AND.W Rx, Ry, #2
        {0xF0FF, 0x0002},
        {0xFFF0, 0xF010}, // TST.W Rz, #2
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000}, // BEQ   loc_xxx
        {0xF8FF, 0x2000}, // MOVS  Rk, #0
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFBE0, 0xF000},
        {0x8000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000},
        {0xF8FF, 0x2000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F04}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn)
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn){
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
        if(!insn)
            return 0;
        insn += 4;
        return ((uintptr_t)insn) - ((uintptr_t)kdata);
    }
    
    insn += 2;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// NOP out the BICNE.W instruction with 4 here.
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_93[] =
    {
        {0xFBF0, 0xF010}, // TST.W   Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFFC0, 0x6840}, // LDR     Rz, [Ry,#4]
        {0xFFC0, 0x68C0}, // LDR     Rs, [Ry,#0xC]
        {0xFF00, 0x4600}, // MOV     Rx, Ry (?)
        {0xFFF0, 0xF000}, // AND.W   Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xFFF0, 0xBF00}, // IT      EQ (?)
        {0xFFF0, 0xF020}, // BICNE.W Rk, Rk, #4 <-
        {0xF0FF, 0x0004}
        //{0xF8FF, 0x2806}, // CMP     Ry, #6
        //{0xFFF0, 0xBF00}, // IT      EQ
    };
    
    const struct find_search_mask search_masks_90[] =
    {
        {0xFBF0, 0xF010}, // TST.W   Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFFC0, 0x6840}, // LDR     Rz, [Ry,#4]
        {0xFFF0, 0xF000}, // AND.W   Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xFFC0, 0x68C0}, // LDR     Rs, [Ry,#0xC]
        {0xFF00, 0x4600}, // MOV     Rx, Ry (?)
        {0xFFF0, 0xBF00}, // IT      EQ (?)
        {0xFFF0, 0xF020}, // BICNE.W Rk, Rk, #4
        {0xF0FF, 0x0004}
        //{0xF8FF, 0x2806}, // CMP     Ry, #6
        //{0xFFF0, 0xBF00}, // IT      EQ
    };
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFBF0, 0xF010}, // TST.W Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F}, // MOV.W Rx, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ
        {0xF8FF, 0x2001}, // MOVEQ Rx, #1
        {0xFFC0, 0x6840}, // LDR             Rz, [Ry,#4]
        {0xFFC0, 0x68C0}, // LDR             Rs, [Ry,#0xC]
        {0xFFF0, 0xF000}, // AND.W           Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xF8FF, 0x2806}, // CMP             Ry, #6
        {0xFBFF, 0xF04F}, // MOV.W           Ry, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ (?)
        {0xF8FF, 0x2001}, // MOVEQ           Ry, #1
        {0xFFC0, 0x4200}, // TST             Ry, Rx
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFBF0, 0xF010},
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xF000},
        {0xF0FF, 0x0006},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xF8FF, 0x2806},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xFFC0, 0x4200},
        {0xFFF0, 0xBF10},
        {0xFFF0, 0xF020},
        {0xF0FF, 0x0004}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
        if(!insn) {
            insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
            if(!insn){
                insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_93) / sizeof(*search_masks_93), search_masks_93);
                if(!insn)
                    return 0;
            }
            insn += 8;
        }
        else
            insn += 15;
    } else
        insn += 17;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint8_t* pixel_format = memmem(kdata, ksize, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof("BBBBBBBBGGGGGGGGRRRRRRRR"));
    if(!pixel_format)
        return 0;
    
    // Find a reference to the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pixel_format - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start)
        return 0;
    
    // Find the first MOV Rx, #1. This is to eventually set PE_state as initialized
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)ref)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_imm(current_instruction) == 1)
        {
            found = 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    // This finds the STR Rx, [Ry] instrunction following that actually writes the #1. We will use Ry to find PE_state.
    found = 0;
    current_instruction += 2;
    uint32_t str_val = insn_str_imm_imm(current_instruction);
    current_instruction += 2;
    
    // Now find the location of PE_state
    uint32_t pe_state = find_pc_rel_value(region, kdata, ksize, current_instruction, insn_str_imm_rn(current_instruction)) + str_val;
    
    if(!pe_state)
        return 0;
    
    // p_boot_args is 0x70 offset in that struct.
    return pe_state + 0x70;
}

uint32_t find_p_bootargs_generic(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint8_t* pixel_format = memmem(kdata, ksize, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof("BBBBBBBBGGGGGGGGRRRRRRRR"));
    if(!pixel_format)
        return 0;
    
    // Find a reference to the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pixel_format - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start)
        return 0;
    
    // Find the first MOV Rx, #1. This is to eventually set PE_state as initialized
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)ref)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_imm(current_instruction) == 1)
        {
            found = 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    int reg = insn_mov_imm_rd(current_instruction);
    
    // This finds the STR Rx, [Ry] instrunction following that actually writes the #1. We will use Ry to find PE_state.
    found = 0;
    while((uintptr_t)current_instruction < (uintptr_t)ref)
    {
        if(insn_is_str_imm(current_instruction) && insn_str_imm_imm(current_instruction) == 0
           && insn_str_imm_postindexed(current_instruction) == 1 && insn_str_imm_wback(current_instruction) == 0
           && insn_str_imm_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    // Now find the location of PE_state
    uint32_t pe_state = find_pc_rel_value(region, kdata, ksize, current_instruction, insn_str_imm_rn(current_instruction));
    if(!pe_state)
        return 0;
    
    // p_boot_args is 0x70 offset in that struct.
    return pe_state + 0x70;
}

uint32_t find_mount_93(uint32_t region, uint8_t* kdata, size_t ksize){
    const struct find_search_mask search_masks[] =
    {
        {0xFF00, 0xD100}, // bne    loc_x
        {0xF0FF, 0x2001}, // movs   rx, #0x1
        {0xFF00, 0xE000}, // b      loc_x
        {0xF0FF, 0x2001}, // movs   rx, #0x1
        {0xFF00, 0xE000}, // b      loc_x
        {0xFFF0, 0xF440}, // orr    fp, fp, #0x10000
        {0xF0FF, 0x3080}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    //insn += 9;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata) + 1;
}

uint32_t find_mount_check(uint32_t region, uint8_t* kdata, size_t ksize) {
    char *version = (char*)[[[UIDevice currentDevice] systemVersion]
                            UTF8String];
    float version_float = strtof(version, 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (version_float == (float)9.3) {
            if (*(uint64_t*)&kdata[i] == 0x2501d1030f01f01b && *(uint32_t*)&kdata[i+0x8] == 0x2501e016) {
                uint32_t mount_common = i + 0x5;
                return mount_common;
            }
        } else if (version_float == (float)9.0) {
            if ((*(uint64_t*)&kdata[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
                uint32_t mount_common = i + 0x5;
                return mount_common;
            }
        } else {
            if (*(uint32_t*)&kdata[i] == 0x0f01f010 && *(uint8_t*)&kdata[i+0x5] == 0xd0 && *(uint32_t*)&kdata[i+0xe] == 0x0f40f010 && *(uint8_t*)&kdata[i+0x13] == 0xd0) {
                uint32_t mount_common = i + 0x5;
                return mount_common;
            }
        }
    }
    return -1;
}

// Replace with NOP
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xF800, 0xD000},
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xF800, 0xE000},
        {0x0000, 0x0000},
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xF800, 0xF000},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xFC00, 0xF000},
        {0x0000, 0x0000}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
        if(!insn)
            return 0;
        insn += 9;
    }
    else
        insn += 14;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// modify the cs flags
uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks[] =
    {
        // :: AMFI.kext
        {0xFFFF, 0xF8DA},   // ldr.w rx, [sl]
        {0x0FFF, 0x0000},
        {0xFFF0, 0xF010},   // tst.w rx, #8
        {0xFFFF, 0x0F08},
        {0xFFF0, 0xBF10},   // it    ne
        {0xFFF0, 0xF440},   // orr   rx, rx, #0x800000
        {0xF0FF, 0x0000},
        {0xFFFF, 0xF8CA},   // str.w rx, [sl]
        {0x0FFF, 0x0000},
        {0xF8FF, 0x2000},   // movs  rk, #0
        {0xFF80, 0xB000},   // add   sp, #x         <- replace @ jump to shellcode
        {0xFFFF, 0xE8BD},   // pop.w {r8, sl, fp}
        {0xFFFF, 0x0D00},
        {0xFFFF, 0xBDF0}    // pop   {r4, r5, r6, r7, pc}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    
    if(!fn_start) {
        return 0;
    }
    
    return ((uintptr_t)fn_start) - ((uintptr_t)kdata) + 20;
}

uint32_t find_amfi_cs_enforcement_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "failed getting entitlements", sizeof("failed getting entitlements"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _cs_enforcement.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_amfi_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "failed getting entitlements", sizeof("failed getting entitlements"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _cs_enforcement.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_PE_i_can_has_kernel_configuration_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* magicStr = memmem(kdata, ksize, "_mapForIO", sizeof("_mapForIO"));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)magicStr - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _IOLog.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_kernel_configuration.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_lwvm_jump(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x6800},  // LDR   Rx, [Ry, #z] <-
        {0xFF00, 0x4400},  // ADD   Rx, Ry
        {0xF800, 0x7800}, //  LDRB  Rx, [Ry, #z]
        {0xFFF0, 0xF010}, //  TST.W Rx, #0x1
        {0xFFFF, 0x0F01},
        {0xFF00, 0xD000}, //  BEQ.N
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    return ((uintptr_t)insn) + 0 - ((uintptr_t)kdata) + 1;
}

uint32_t find_sandbox_mac_policy_ops(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* sbStr = memmem(kdata, ksize, "Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy"));
    if(!sbStr)
        return 0;
    uint32_t fullname = (uint32_t)sbStr - (uintptr_t)kdata;
    
    uint32_t search[1];
    search[0] = fullname+region;
    
    uint8_t* findPtr = memmem(kdata, ksize, &search, 4);
    if(!findPtr)
        return 0;
    uint32_t mpc_top = (uint32_t)findPtr - (uintptr_t)kdata - 4;
    uint32_t ops_off = mpc_top += 0x10;
    uint32_t ops = *(uint32_t*)(kdata + ops_off) - region;
    return ops;
}

uint32_t find_sb_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops)
{
    //ops = 0;
    
    uint8_t* magicStr = memmem(kdata, ksize, "amfi_copy_seatbelt_profile_names() failed", sizeof("amfi_copy_seatbelt_profile_names() failed"));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)magicStr - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _strlen.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_sb_vfs_rootvnode_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops)
{
    //ops = 0;
    
    const struct find_search_mask search_masks[] =
    {
        //{0xFF00, 0x4600}, // MOV   Rx, Ry
        //{0xF800, 0xF000}, // BL    _vfs_flags.stub
        //{0xF800, 0xF800},
        {0xFBF0, 0xF010}, // TST.W Rx, #y (?)
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}, // BNE   x
        {0xF8FF, 0x2000}, // MOVS  Rk, #0
        {0xFF00, 0xE000}, // B     x
        {0xF800, 0xF000}, // BL    _vfs_rootvnode.stub
        {0xF800, 0xF800},
        {0xFF00, 0x4600}  // MOV   Rx, Ry
    };
    
    uint16_t* ref = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ref)
        return 0;
    
    // find 'BL _vfs_rootvnode.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_rootvnode_offset(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t fn)
{
    uint16_t* fn_start = (uint16_t*)(kdata+(fn-region));
    if(!fn_start) return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) != 7)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_allproc(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const char *str = "shutdownwait";
    uint8_t* point = memmem(kdata, ksize, str, strlen(str));
    if(!point)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_movt(current_instruction))
        {
            found = 1;
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    found = 0;
    int rd;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) != 7)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    uint32_t val = find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
    if(!val)
        return 0;
    
    uint16_t* ref2 = find_literal_ref(region, kdata, ksize, (uint16_t*) current_instruction, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // LDR
    int found2 = 0;
    int val2 = 0;
    uint16_t* current_instruction2 = ref2;
    while((uintptr_t)current_instruction2 < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_ldr_imm(current_instruction2))
        {
            found2 = 1;
            val2 = insn_ldr_imm_imm(current_instruction2) << 2;
            current_instruction2 += insn_is_32bit(current_instruction2) ? 2 : 1;
            break;
        }
        current_instruction2 += insn_is_32bit(current_instruction2) ? 2 : 1;
    }
    
    if(!found2)
        return 0;
    
    if(!val2)
        return 0;
    
    return val + val2;
}

// Borrowed this function from p0laris, thanks SPV!
uint32_t find_tfp0(uint32_t region, uint8_t* kdata, size_t ksize) {
    for (uint32_t i = 0; i < ksize; i++) {
        if (*(uint16_t*)&kdata[i] == 0x4630 && *(uint64_t*)&kdata[i + 6] == 0xf0000f00f1ba4682 && *(uint32_t*)&kdata[i + 0x10] == 0xf0014650) {
            for (int a = i; a > (i - 0x30); a -= 2) {
                if (*(uint16_t*)&kdata[a] == 0xb5f0) {
                    for (int e = a; e < (a + 0x20); e += 2) {
                        if (*(uint16_t*)&kdata[e] == 0x2e00) {
                            uint32_t tfp0 = e + 0x4;
                            printf("[i] Found tfp0 patch region: 0x%08x\n", tfp0);
                            return tfp0;
                        }
                    }
                }
            }
        }
    }
    return -1;
}

uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize) {
    char* seatbelt_sandbox_policy = memmem(kdata,
                                           ksize,
                                           "Seatbelt sandbox policy",
                                           strlen("Seatbelt sandbox policy"));
    printf("  -- [i] seatbelt_sandbox_policy 0x%08lx\n",
         (uintptr_t)seatbelt_sandbox_policy);
    if (!seatbelt_sandbox_policy)
        return -1;
    
    uint32_t seatbelt =   (uintptr_t)seatbelt_sandbox_policy
    - (uintptr_t)kdata
    + region;
    printf("  -- [i] seatbelt: 0x%08x\n", seatbelt);
    
    char* seatbelt_sandbox_policy_ptr = memmem(kdata,
                                               ksize,
                                               (char*)&seatbelt,
                                               sizeof(seatbelt));
    
    printf("  -- [i] seatbelt_sandbox_policy_ptr 0x%08lx\n",
         (uintptr_t)seatbelt_sandbox_policy_ptr);
    if (!seatbelt_sandbox_policy_ptr)
        return -1;
    
    uint32_t ptr_to_seatbelt =   (uintptr_t)seatbelt_sandbox_policy_ptr
    - (uintptr_t)kdata;
    uint32_t sbops = ptr_to_seatbelt + 0x24;

    return sbops;
}

uint32_t find_sb_i_can_has_debugger(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
    if (!ptr) {
        ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    }
    if (!ptr)
        return 0;
    
    uint32_t sbdbg = (uintptr_t)ptr + 8 - ((uintptr_t)kdata);
    return sbdbg;
}

uint32_t find_lwvm_call(uint32_t region, uint8_t* kdata, size_t ksize) {
    char* faceable = memmem(kdata, ksize, "\xce\xab\x1e\xef\xfa\xce\xab\x1e", 8);
    if (!faceable)
        return -1;
    char* lwvm_call_pointer = faceable + 0x78;
    uint32_t lwvm_call = (uintptr_t)lwvm_call_pointer - (uintptr_t)kdata;
    return lwvm_call;
}

uint32_t find_lwvm_call_offset(uint32_t region, uint8_t* kdata, size_t ksize) {
    for (uint32_t i = 0; i < ksize; i += 2) {
        if (*(uint64_t*)&kdata[i] == 0xf010798044406da0 && *(uint32_t*)&kdata[i+0x8] == 0xd0060f01 && *(uint16_t*)&kdata[i+0xC] == 0x4620) {
            uint32_t lwvm_call_offset = i + 1;
            return lwvm_call_offset;
        }
    }
    return -1;
}

uint32_t find_amfi_file_check_mmap(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint8_t* rootless = memmem(kdata, ksize, "com.apple.rootless.install", sizeof("com.apple.rootless.install"));
    if (!rootless)
        return 0;

    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)rootless - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    int i=0;
    while (1){
        if (i>16)
            return 0;
        if ((ref[i] & 0xfff0) == 0xbf10)
            break;
        i++;
    }
    ref += (i-1);
    uint32_t amfi_file_check_mmap = (uintptr_t)ref - (uintptr_t)kdata;
    return amfi_file_check_mmap;
}

/*
THANKS TO zachary7829 FOR THESE HARDCODED OFFSETS FOR PE_I_CAN_HAS_DEBUGGER. MY PATCH REFUSED TO WORK FOR SOME REASON SO IT'S HARDCODED FOR NOW.
*/

NSString *KernelVersion(void) {
    size_t size;
    sysctlbyname("kern.version", NULL, &size, NULL, 0);
    char *kernelVersion = malloc(size);
    sysctlbyname("kern.version", kernelVersion, &size, NULL, 0);
    char *newkernv = malloc(size - 44);
    char *semicolon = strchr(kernelVersion, '~');
    int indexofsemi = (int)(semicolon - kernelVersion);
    int indexofrootxnu = indexofsemi;
    while (kernelVersion[indexofrootxnu - 1] != '-') {
        indexofrootxnu -= 1;
    }
    memcpy(newkernv, &kernelVersion[indexofrootxnu], indexofsemi - indexofrootxnu + 2);
    newkernv[indexofsemi - indexofrootxnu + 2] = '\0';
    return [NSString stringWithUTF8String:newkernv];
}

// Thanks to zachary7829

uint32_t find_PE_i_can_has_debugger_uno(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_1;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        if ([[NSArray arrayWithObjects:@"3248.61.1~1", nil] containsObject:KernelVersion()]) { //9.3.5-9.3.6
            PE_i_can_has_debugger_1 = 0x3a82c4;
        } else if ([[NSArray arrayWithObjects:@"3248.60.9~1", nil] containsObject:KernelVersion()]) { //9.3.3b4-9.3.4
            PE_i_can_has_debugger_1 = 0x3a82d4;
        } else if ([[NSArray arrayWithObjects:@"3248.60.8~1", nil] containsObject:KernelVersion()]) { //9.3.3b3
            PE_i_can_has_debugger_1 = 0x3a8424;
        } else if ([[NSArray arrayWithObjects:@"3248.60.4~1", nil] containsObject:KernelVersion()]) { //9.3.3b2
            PE_i_can_has_debugger_1 = 0x3a81f4;
        } else if ([[NSArray arrayWithObjects:@"3248.60.3~3", nil] containsObject:KernelVersion()]) { //9.3.3b1
            PE_i_can_has_debugger_1 = 0x3a8294;
        } else if ([[NSArray arrayWithObjects:@"3248.50.21~4", nil] containsObject:KernelVersion()]) { //9.3.2b3-9.3.2
            PE_i_can_has_debugger_1 = 0x3a7ff4;
        } else if ([[NSArray arrayWithObjects:@"3248.50.20~1", nil] containsObject:KernelVersion()]) { //9.3.2b2
            PE_i_can_has_debugger_1 = 0x3a7ff4;
        } else if ([[NSArray arrayWithObjects:@"3248.50.18~1", nil] containsObject:KernelVersion()]) { //9.3.2b1
            PE_i_can_has_debugger_1 = 0x3a7ff4;
        } else if ([[NSArray arrayWithObjects:@"3248.41.4~2", nil] containsObject:KernelVersion()]) { //9.3b7-9.3.1
            PE_i_can_has_debugger_1 = 0x3a7ea4;
        } else if ([[NSArray arrayWithObjects:@"3248.41.4~3", nil] containsObject:KernelVersion()]) { //9.3b5-9.3b6
            PE_i_can_has_debugger_1 = 0x3a7ea4;
        } else if ([[NSArray arrayWithObjects:@"3248.41.3~1", nil] containsObject:KernelVersion()]) { //9.3b4
            PE_i_can_has_debugger_1 = 0x3a7ea4;
        } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b3
            PE_i_can_has_debugger_1 = 0x3a7cf4;
        } else if ([[NSArray arrayWithObjects:@"3248.40.166.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b2
            PE_i_can_has_debugger_1 = 0x3af964;
        } else if ([[NSArray arrayWithObjects:@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3a77f4;
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2", nil] containsObject:KernelVersion()]) { //9.2.1b1-9.2.1
            PE_i_can_has_debugger_1 = 0x3a1434;
        } else if ([[NSArray arrayWithObjects:@"3248.21.2~1", nil] containsObject:KernelVersion()]) { //9.2b4-9.2
            PE_i_can_has_debugger_1 = 0x3a12c4;
        } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]) { //9.2b3
            PE_i_can_has_debugger_1 = 0x3a1164;
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]) { //9.2b2
            PE_i_can_has_debugger_1 = 0x3a0a94;
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]) { //9.2b1
            PE_i_can_has_debugger_1 = 0x3ac744;
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3aa734;
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_1 = 0x3aa654;
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3a8fc4;
        } else if ([[NSArray arrayWithObjects:@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5
            PE_i_can_has_debugger_1 = 0x3a8f44;
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            PE_i_can_has_debugger_1 = 0x3a7394;
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            PE_i_can_has_debugger_1 = 0x3a8444;
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
            PE_i_can_has_debugger_1 = 0x3ad524;
        } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]){ //9.0b1
            PE_i_can_has_debugger_1 = 0x45ad20;
        } else {
            PE_i_can_has_debugger_1 = 0x3f4dc0;
        }
    } else {
        if ([[NSArray arrayWithObjects:@"3248.61.1~1", nil] containsObject:KernelVersion()]) { //9.3.5-9.3.6
            PE_i_can_has_debugger_1 = 0x3afee4;
        } else if ([[NSArray arrayWithObjects:@"3248.60.9~1", nil] containsObject:KernelVersion()]) { //9.3.3b4-9.3.4
            PE_i_can_has_debugger_1 = 0x3aff14;
        } else if ([[NSArray arrayWithObjects:@"3248.60.8~1", nil] containsObject:KernelVersion()]) { //9.3.3b3
            PE_i_can_has_debugger_1 = 0x3b0094;
        } else if ([[NSArray arrayWithObjects:@"3248.60.4~1", nil] containsObject:KernelVersion()]) { //9.3.3b2
            PE_i_can_has_debugger_1 = 0x3afcf4;
        } else if ([[NSArray arrayWithObjects:@"3248.60.3~3", nil] containsObject:KernelVersion()]) { //9.3.3b1
            PE_i_can_has_debugger_1 = 0x3afda4;
        } else if ([[NSArray arrayWithObjects:@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1", nil] containsObject:KernelVersion()]){
            PE_i_can_has_debugger_1 = 0x3afb14;
        } else if ([[NSArray arrayWithObjects:@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1", nil] containsObject:KernelVersion()]){
            PE_i_can_has_debugger_1 = 0x3afaf4;
        } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b3
            PE_i_can_has_debugger_1 = 0x3af914;
        } else if ([[NSArray arrayWithObjects:@"3248.40.166.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b2
            PE_i_can_has_debugger_1 = 0x3af964;
        } else if ([[NSArray arrayWithObjects:@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3af3e4;
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2", nil] containsObject:KernelVersion()]){ //9.2.1b1-9.2.1
            PE_i_can_has_debugger_1 = 0x3a8764;
        } else if ([[NSArray arrayWithObjects:@"3248.21.2~1", nil] containsObject:KernelVersion()]){ //9.2b4-9.2
            PE_i_can_has_debugger_1 = 0x3a85e4;
        } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3
            PE_i_can_has_debugger_1 = 0x3a83b4;
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            PE_i_can_has_debugger_1 = 0x3a7c54;
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            PE_i_can_has_debugger_1 = 0x3b3c84;
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3b0694;
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_1 = 0x3b0644;
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_1 = 0x3af014;
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            PE_i_can_has_debugger_1 = 0x3ae364;
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            PE_i_can_has_debugger_1 = 0x3b01a4;
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            PE_i_can_has_debugger_1 = 0x3b4b94;
        } else {
            PE_i_can_has_debugger_1 = 0x461e40;
        }
    }
    return PE_i_can_has_debugger_1;
}

// Thanks to zachary7829.

uint32_t find_PE_i_can_has_debugger_dos(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_2;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_2 = 0x456070;
        } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]){
            PE_i_can_has_debugger_2 = 0x456080;
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2", nil] containsObject:KernelVersion()]){
            PE_i_can_has_debugger_2 = 0x44f070;
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            PE_i_can_has_debugger_2 = 0x44d870;
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            PE_i_can_has_debugger_2 = 0x459870;
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_2 = 0x457860;
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_2 = 0x4577e0;
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_2 = 0x4567d0;
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]){ //9.0b4
            PE_i_can_has_debugger_2 = 0x454750;
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]){ //9.0b3
            PE_i_can_has_debugger_2 = 0x455740;
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
            PE_i_can_has_debugger_2 = 0x45c630;
        } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]) { //9.0b1
            PE_i_can_has_debugger_2 = 0x459520;
        } else {
            PE_i_can_has_debugger_2 = 0x3f2dc0;
        }
    } else {
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
            PE_i_can_has_debugger_2 = 0x45e1a0;
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2", nil] containsObject:KernelVersion()]){
            PE_i_can_has_debugger_2 = 0x456190;
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            PE_i_can_has_debugger_2 = 0x455990;
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            PE_i_can_has_debugger_2 = 0x461990;
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_2 = 0x45e980;
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_2 = 0x45d900;
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) {
            PE_i_can_has_debugger_2 = 0x45c8f0;
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            PE_i_can_has_debugger_2 = 0x45b870;
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            PE_i_can_has_debugger_2 = 0x45d860;
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            PE_i_can_has_debugger_2 = 0x464750;
        } else { //9.0b1
            PE_i_can_has_debugger_2 = 0x460640;
        }
    }
    return PE_i_can_has_debugger_2;
}

