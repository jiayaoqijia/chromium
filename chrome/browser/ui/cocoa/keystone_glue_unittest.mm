// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import <Foundation/Foundation.h>
#import <objc/objc-class.h>

#import "chrome/browser/ui/cocoa/keystone_glue.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

@interface FakeGlueRegistration : NSObject
@end


@implementation FakeGlueRegistration

// Send the notifications that a real KeystoneGlue object would send.

- (void)checkForUpdate {
  NSNumber* yesNumber = [NSNumber numberWithBool:YES];
  NSString* statusKey = @"Status";
  NSDictionary* dictionary = [NSDictionary dictionaryWithObject:yesNumber
                                                         forKey:statusKey];
  NSNotificationCenter* center = [NSNotificationCenter defaultCenter];
  [center postNotificationName:@"KSRegistrationCheckForUpdateNotification"
                        object:nil
                      userInfo:dictionary];
}

- (void)startUpdate {
  NSNotificationCenter* center = [NSNotificationCenter defaultCenter];
  [center postNotificationName:@"KSRegistrationStartUpdateNotification"
                        object:nil];
}

@end


@interface FakeKeystoneGlue : KeystoneGlue {
 @public
  BOOL upToDate_;
  NSString *latestVersion_;
  BOOL successful_;
  int installs_;
}

- (void)fakeAboutWindowCallback:(NSNotification*)notification;
@end


@implementation FakeKeystoneGlue

- (id)init {
  if ((self = [super init])) {
    // some lies
    upToDate_ = YES;
    latestVersion_ = @"foo bar";
    successful_ = YES;
    installs_ = 1010101010;

    // Set up an observer that takes the notification that the About window
    // listens for.
    NSNotificationCenter* center = [NSNotificationCenter defaultCenter];
    [center addObserver:self
               selector:@selector(fakeAboutWindowCallback:)
                   name:kAutoupdateStatusNotification
                 object:nil];
  }
  return self;
}

- (void)dealloc {
  [[NSNotificationCenter defaultCenter] removeObserver:self];
  [super dealloc];
}

// For mocking
- (NSDictionary*)infoDictionary {
  NSDictionary* dict = [NSDictionary dictionaryWithObjectsAndKeys:
                                     @"http://foo.bar", @"KSUpdateURL",
                                     @"com.google.whatever", @"KSProductID",
                                     @"0.0.0.1", @"KSVersion",
                                     nil];
  return dict;
}

// For mocking
- (BOOL)loadKeystoneRegistration {
  return YES;
}

// Confirms certain things are happy
- (BOOL)dictReadCorrectly {
  return ([url_ isEqual:@"http://foo.bar"] &&
          [productID_ isEqual:@"com.google.whatever"] &&
          [version_ isEqual:@"0.0.0.1"]);
}

// Confirms certain things are happy
- (BOOL)hasATimer {
  return timer_ ? YES : NO;
}

- (void)addFakeRegistration {
  registration_ = [[FakeGlueRegistration alloc] init];
}

- (void)fakeAboutWindowCallback:(NSNotification*)notification {
  NSDictionary* dictionary = [notification userInfo];
  AutoupdateStatus status = static_cast<AutoupdateStatus>(
      [[dictionary objectForKey:kAutoupdateStatusStatus] intValue]);

  if (status == kAutoupdateAvailable) {
    upToDate_ = NO;
    latestVersion_ = [dictionary objectForKey:kAutoupdateStatusVersion];
  } else if (status == kAutoupdateInstallFailed) {
    successful_ = NO;
    installs_ = 0;
  }
}

// Confirm we look like callbacks with nil NSNotifications
- (BOOL)confirmCallbacks {
  return (!upToDate_ &&
          (latestVersion_ == nil) &&
          !successful_ &&
          (installs_ == 0));
}

@end


namespace {

class KeystoneGlueTest : public PlatformTest {
};

// DISABLED because the mocking isn't currently working.
TEST_F(KeystoneGlueTest, DISABLED_BasicGlobalCreate) {
  // Allow creation of a KeystoneGlue by mocking out a few calls
  SEL ids = @selector(infoDictionary);
  IMP oldInfoImp_ = [[KeystoneGlue class] instanceMethodForSelector:ids];
  IMP newInfoImp_ = [[FakeKeystoneGlue class] instanceMethodForSelector:ids];
  Method infoMethod_ = class_getInstanceMethod([KeystoneGlue class], ids);
  method_setImplementation(infoMethod_, newInfoImp_);

  SEL lks = @selector(loadKeystoneRegistration);
  IMP oldLoadImp_ = [[KeystoneGlue class] instanceMethodForSelector:lks];
  IMP newLoadImp_ = [[FakeKeystoneGlue class] instanceMethodForSelector:lks];
  Method loadMethod_ = class_getInstanceMethod([KeystoneGlue class], lks);
  method_setImplementation(loadMethod_, newLoadImp_);

  KeystoneGlue *glue = [KeystoneGlue defaultKeystoneGlue];
  ASSERT_TRUE(glue);

  // Fix back up the class to the way we found it.
  method_setImplementation(infoMethod_, oldInfoImp_);
  method_setImplementation(loadMethod_, oldLoadImp_);
}

// DISABLED because the mocking isn't currently working.
TEST_F(KeystoneGlueTest, DISABLED_BasicUse) {
  FakeKeystoneGlue* glue = [[[FakeKeystoneGlue alloc] init] autorelease];
  [glue loadParameters];
  ASSERT_TRUE([glue dictReadCorrectly]);

  // Likely returns NO in the unit test, but call it anyway to make
  // sure it doesn't crash.
  [glue loadKeystoneRegistration];

  // Confirm we start up an active timer
  [glue registerWithKeystone];
  ASSERT_TRUE([glue hasATimer]);
  [glue stopTimer];

  // Brief exercise of callbacks
  [glue addFakeRegistration];
  [glue checkForUpdate];
  [glue installUpdate];
  ASSERT_TRUE([glue confirmCallbacks]);
}

}  // namespace
