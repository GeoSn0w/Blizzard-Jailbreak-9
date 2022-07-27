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
int blizzardGetTFP0(void);
kaddr_t blizzardGetAllproc(void);
int blizzardGetRoot(void);
int blizzardEscapeSandbox(void);
int blizzardPatchPMAP(void);
int patch_mount_common(void);
int patch_cs_enforcement_disable(void);
int patch_sb_i_can_has_debugger(void);
int blizzardRemountRootFS(void);
#endif /* blizzardJailbreak_h */
