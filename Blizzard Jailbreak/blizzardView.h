//
//  blizzardView.h
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN
UIBarButtonItem* dismissKeyboardButton;
@interface blizzardView : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *blizzardInit;
@property (weak, nonatomic) IBOutlet UITextField *nonceField;
@property (weak, nonatomic) IBOutlet UISwitch *shouldUnjailbreakBlizzard;
@property (weak, nonatomic) IBOutlet UISwitch *exportTfp0Toggle;
@property (weak, nonatomic) IBOutlet UISegmentedControl *zebraORCydiaToggle;

@end

NS_ASSUME_NONNULL_END
