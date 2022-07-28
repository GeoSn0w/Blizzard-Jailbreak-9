//
//  BlizzardLog.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2022 GeoSn0w. All rights reserved.
//

#import "BlizzardLog.h"
#import "../Blizzard Jailbreak/blizzardJailbreak.h"
#import "../Exploits/Phoenix Exploit/exploit.h"

#define currentVer(v)  ([[[UIDevice currentDevice] systemVersion] compare:@v options:NSNumericSearch] != NSOrderedDescending)
@interface BlizzardLog()
@end

static BlizzardLog *BlizzLogger;

@implementation BlizzardLog

+ (instancetype)BlizzLogger {
    return BlizzLogger;
}

int dismissButtonActionType = 0;
int IS_BLIZZARD_DEBUG = 1;
int shouldUnjailbreak = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    if (IS_BLIZZARD_DEBUG != 1){
        [self redirectSTD:STDOUT_FILENO];
    }
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        blizzardGetTFP0();
        dispatch_async(dispatch_get_main_queue(), ^{
            [self redirectSTD:STDOUT_FILENO];
            NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
            [self.uiLogView scrollRangeToVisible:lastLine];
        });
        
    });
    
}
-(void) runJailbreak {
    if (currentVer("9.3.5")){
        extern char *get_current_deviceModel(void);
        printf("Version: %s\n", [[[UIDevice currentDevice] systemVersion] UTF8String]);
        blizzardGetTFP0();
    } else if (currentVer("9.3.4")){
    }
}
- (IBAction)dismissLogWindow:(id)sender {
    if (dismissButtonActionType == 0){
        [self dismissViewControllerAnimated:YES completion:nil];
    }
}

-(void)textViewDidChange:(UITextView *)textView
{
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
}

- (void)redirectNotificationHandle:(NSNotification *)nf{
    NSData *data = [[nf userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    self.uiLogView.text = [NSString stringWithFormat:@"%@\n%@",self.uiLogView.text, str];
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
    [[nf object] readInBackgroundAndNotify];
}

- (void)redirectSTD:(int )fd{
    setvbuf(stdout, nil, _IONBF, 0);
    NSPipe * pipe = [NSPipe pipe] ;
    NSFileHandle *pipeReadHandle = [pipe fileHandleForReading] ;
    dup2([[pipe fileHandleForWriting] fileDescriptor], fd) ;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(redirectNotificationHandle:)
                                                 name:NSFileHandleReadCompletionNotification
                                               object:pipeReadHandle] ;
    [pipeReadHandle readInBackgroundAndNotify];
}

@end
