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
#include <sys/mman.h>
#include <spawn.h>
#include "BlizzardLog.h"
#import "../Exploits/Phoenix Exploit/exploit.h"

mach_port_t kern_task = 0;

int blizzardGetTFP0(){
    printf("Blizzard is exploting the kernel...\n");
    exploit();
    kern_task  = tfp0;
    
    if (kern_task != 0){
        printf("Got tfp0: %0xllx\n", kern_task);
    } else {
        printf("FAILED to obtain Kernel Task Port!\n");
    }
    return 0;
}

