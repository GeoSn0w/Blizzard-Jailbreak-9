//
//  KernMemory.h
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 7/27/22.
//  Copyright © 2022 GeoSn0w. All rights reserved.
//

#ifndef KernMemory_h
#define KernMemory_h
#include <mach/mach.h>
#include "../Common/CommonStuff.h"

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

void copyin(void* to, kaddr_t from, size_t size);
void copyout(kaddr_t to, void* from, size_t size);


uint32_t ReadKernel32(kaddr_t addr);
kaddr_t WriteKernel32(kaddr_t addr, uint32_t val);
__unused kaddr_t wk16(kaddr_t addr, uint16_t val);
__unused kaddr_t WriteKernel8(kaddr_t addr, uint8_t val);

kaddr_t rkptr(kaddr_t addr);
kaddr_t wkptr(kaddr_t addr, kaddr_t val);
#endif /* KernMemory_h */
