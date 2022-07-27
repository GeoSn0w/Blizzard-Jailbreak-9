#ifndef PATCHFINDER32_H
#define PATCHFINDER32_H

#ifndef __LP64__

#include <stdint.h>
#include <string.h>

// Helper gadget.
uint32_t find_ret0_gadget(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_ret1_gadget(uint32_t region, uint8_t* kdata, size_t ksize);

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_vnode_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize);

//
uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// NOP out the conditional branch here.
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Change the conditional branch here to an unconditional branch.
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_p_bootargs_generic(uint32_t region, uint8_t* kdata, size_t ksize);

// No ideas...
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount_93(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_cs_enforcement_got(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_PE_i_can_has_kernel_configuration_got(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_lwvm_jump(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_mac_policy_ops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops);
uint32_t find_sb_vfs_rootvnode_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops);
uint32_t find_rootvnode_offset(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t fn);
uint32_t find_allproc(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize);

#endif
#endif
