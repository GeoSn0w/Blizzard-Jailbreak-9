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
#endif /* blizzardJailbreak_h */