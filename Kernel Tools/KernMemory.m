#import <Foundation/Foundation.h>
#include "../Common/CommonStuff.h"
#include "KernMemory.h"
#include "../Exploits/Phoenix Exploit/exploit.h"

extern mach_port_t tfp0;

void copyin(void* to, kaddr_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(kaddr_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t ReadKernel32(kaddr_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

kaddr_t WriteKernel32(kaddr_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

__unused kaddr_t wk16(kaddr_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}

__unused kaddr_t WriteKernel8(kaddr_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

kaddr_t rkptr(kaddr_t addr){
    return ReadKernel32(addr);
}

kaddr_t wkptr(kaddr_t addr, kaddr_t val) {
    return WriteKernel32(addr, val);
}
