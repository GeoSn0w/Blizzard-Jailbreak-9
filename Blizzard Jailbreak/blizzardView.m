//
//  blizzardView.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import "blizzardView.h"
#include "blizzardJailbreak.h"
#import <sys/utsname.h>
#include "../Common/rebootDevice.h"

BOOL shouldRemoveBlizzardAction = false;

//For iOS version detection
#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)

@interface blizzardView () <UITextFieldDelegate>

@end

@implementation blizzardView

- (void)viewDidLoad {
    [super viewDidLoad];
    printf("Blizzard Jailbreak\nby GeoSn0w (@FCE365)\n\nAn Open-Source Jailbreak for you to study and dissect :-)\n");
    
    struct utsname uts;
    uname(&uts);
    
    if (strstr(uts.version, "Blizzard")) {
        printf("%s %s %s\n", uts.sysname, uts.version, uts.release);
        printf("[i] Already Jailbroken\n");
        self->_blizzardInit.enabled = NO;
        [self->_blizzardInit setTitle:@"JAILBROKEN" forState:UIControlStateDisabled];
    }
}
- (IBAction)blizzardUnjailbreakSwitch:(id)sender {
    if (_shouldUnjailbreakBlizzard.isOn == true){
        shouldRemoveBlizzardAction = true;
        [self->_blizzardInit setTitle:@"Remove Blizzard" forState:UIControlStateNormal];
        [_blizzardInit setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
        
    } else {
        shouldRemoveBlizzardAction = false;
        [self->_blizzardInit setTitle:@"Jailbreak" forState:UIControlStateNormal];
    }
}

- (IBAction)blizzardInit:(id)sender {
    if (SYSTEM_VERSION_GREATER_THAN(@"8.4.1") && SYSTEM_VERSION_LESS_THAN(@"9.3.7")){
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_blizzardInit.enabled = NO;
            [self->_blizzardInit setTitle:@"Exploiting..." forState:UIControlStateDisabled];
        });
        
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            if (runKernelExploit() == 0){
                dispatch_async(dispatch_get_main_queue(), ^{
                    self->_blizzardInit.enabled = NO;
                    [self->_blizzardInit setTitle:@"Exploit SUCCESS!" forState:UIControlStateDisabled];
                });
                
                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                    if (getAllProcStub() == 0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            self->_blizzardInit.enabled = NO;
                            [self->_blizzardInit setTitle:@"Got AllProc!" forState:UIControlStateDisabled];
                        });
                        dispatch_async(dispatch_get_global_queue(0, 0), ^{
                            if (getRootStub() == 0){
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    self->_blizzardInit.enabled = NO;
                                    [self->_blizzardInit setTitle:@"Got ROOT!" forState:UIControlStateDisabled];
                                });
                                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                                    if (patchSandboxStub() == 0){
                                        dispatch_async(dispatch_get_main_queue(), ^{
                                            self->_blizzardInit.enabled = NO;
                                            [self->_blizzardInit setTitle:@"Escaped Sandbox!" forState:UIControlStateDisabled];
                                        });
                                        dispatch_async(dispatch_get_main_queue(), ^{
                                            self->_blizzardInit.enabled = NO;
                                            [self->_blizzardInit setTitle:@"Patching Kernel..." forState:UIControlStateDisabled];
                                        });
                                        dispatch_async(dispatch_get_global_queue(0, 0), ^{
                                            if (applyKernelPatchesStub() == 0){
                                                dispatch_async(dispatch_get_main_queue(), ^{
                                                    self->_blizzardInit.enabled = NO;
                                                    [self->_blizzardInit setTitle:@"Kernel Patched!" forState:UIControlStateDisabled];
                                                });
                                                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                                                    if (remountROOTFSStub() == 0){
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            self->_blizzardInit.enabled = NO;
                                                            [self->_blizzardInit setTitle:@"ROOT FS Remounted!" forState:UIControlStateDisabled];
                                                        });
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            self->_blizzardInit.enabled = NO;
                                                            [self->_blizzardInit setTitle:@"Preparing System..." forState:UIControlStateDisabled];
                                                        });
                                                        dispatch_async(dispatch_get_global_queue(0, 0), ^{
                                                            if (shouldRemoveBlizzardAction == true) {
                                                                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                                                                    if (unjailbreakBlizzard() == 0) {
                                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                                            self->_blizzardInit.enabled = NO;
                                                                            [self->_blizzardInit setTitle:@"Success! Rebooting!" forState:UIControlStateDisabled];
                                                                        });
                                                                        reboot(RB_QUICK);
                                                                    }
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        self->_blizzardInit.enabled = NO;
                                                                        [self->_blizzardInit setTitle:@"Removing Blizzard..." forState:UIControlStateDisabled];
                                                                    });
                                                                });
                                                            } else {
                                                                if (installBootstrapStub() == 0){
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        self->_blizzardInit.enabled = NO;
                                                                        [self->_blizzardInit setTitle:@"Bootstrap SUCCESS" forState:UIControlStateDisabled];
                                                                    });
                                                                    
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        self->_blizzardInit.enabled = NO;
                                                                        [self->_blizzardInit setTitle:@"JAILBROKEN!" forState:UIControlStateDisabled];
                                                                    });
                                                                    
                                                                } else {
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        self->_blizzardInit.enabled = NO;
                                                                        [self->_blizzardInit setTitle:@"Bootstrap FAILED!" forState:UIControlStateDisabled];
                                                                    });
                                                                }
                                                            }
                                                        });
                                                    } else {
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            self->_blizzardInit.enabled = NO;
                                                            [self->_blizzardInit setTitle:@"Remount FAILED!" forState:UIControlStateDisabled];
                                                        });
                                                    }
                                                });
                                            } else {
                                                dispatch_async(dispatch_get_main_queue(), ^{
                                                    self->_blizzardInit.enabled = NO;
                                                    [self->_blizzardInit setTitle:@"Patching FAILED!" forState:UIControlStateDisabled];
                                                });
                                            }
                                        });
                                    } else {
                                        dispatch_async(dispatch_get_main_queue(), ^{
                                            self->_blizzardInit.enabled = NO;
                                            [self->_blizzardInit setTitle:@"Sandbox FAILED!" forState:UIControlStateDisabled];
                                        });
                                    }
                                });
                            } else {
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    self->_blizzardInit.enabled = NO;
                                    [self->_blizzardInit setTitle:@"ROOT FAILED!" forState:UIControlStateDisabled];
                                });
                            }
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            self->_blizzardInit.enabled = NO;
                            [self->_blizzardInit setTitle:@"AllProc FAILED!" forState:UIControlStateDisabled];
                        });
                    }
                });
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self->_blizzardInit.enabled = NO;
                    [self->_blizzardInit setTitle:@"Exploit FAILED!" forState:UIControlStateDisabled];
                });
            }
        });
        
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_blizzardInit.enabled = NO;
            [self->_blizzardInit setTitle:@"UNSUPPORTED" forState:UIControlStateDisabled];
        });
    }
    
  
    
}
- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}
@end
