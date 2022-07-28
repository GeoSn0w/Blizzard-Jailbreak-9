//
//  BlizzardSpawnerTools.c
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/11/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#include "BlizzardSpawnerTools.h"
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <unistd.h>
#import <spawn.h>
#import <sys/mman.h>
#import <sys/attr.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <CommonCrypto/CommonDigest.h>

extern char **environ;
void spawnBinaryAtPath(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;
    
    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);
    char *argv[] = {"sh", "-c", cmd_, NULL};
    int status;
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
    
    if (status == 0) {
        printf("   -- [i] Child Process ID: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                printf("   -- [i] Child status: %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        printf("   -- [i] Status of posix_spawn: %s\n", strerror(status));
    }
    return;
}
