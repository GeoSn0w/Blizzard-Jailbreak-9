//
//  blizzardJailbreak.h
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#ifndef blizzardJailbreak_h
#define blizzardJailbreak_h

#include <stdio.h>
typedef uint32_t kaddr_t;
int runKernelExploit(void);
int getAllProcStub(void);
int blizzardGetTFP0(void);
int getRootStub(void);
int patchSandboxStub(void);
int applyKernelPatchesStub(void);
int remountROOTFSStub(void);
int installBootstrapStub(void);
int updateKernelVersionString(void);
kaddr_t blizzardGetAllproc(void);
int blizzardGetRoot(void);
int blizzardEscapeSandbox(void);
int blizzardPatchPMAP(void);
int patch_mount_common(void);
int patch_cs_enforcement_disable(void);
int patch_sb_i_can_has_debugger(void);
int blizzardRemountRootFS(void);
int blizzardInstallBootstrap(const char *tarbin, const char* bootstrap, const char * launchctl);
int initWithCydiaFixup(void);
int fixBinaryPermissions(void);
int copyBaseBinariesToPath(void);
int installBlizzardMarkerAthPath(void);
int getBootstrapReady(void);
int fixSpringBoardApplications(void);
int loadBlizzardLaunchDaemons(void);
int respringDeviceNow(void);
int blizzardPostInstFixup(void);
int checkIfBootstrapPresent(void);
int patch_amfi_pe_i_can_has_debugger(void);
int patch_second_amfi_pe_i_can_has_debugger(void);
int patch_amfi_mmap(void);
int installDropbearSSH(void);
#endif /* blizzardJailbreak_h */
