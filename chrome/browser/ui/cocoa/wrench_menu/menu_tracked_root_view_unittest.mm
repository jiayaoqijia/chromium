// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import <Cocoa/Cocoa.h>

#include "base/scoped_nsobject.h"
#import "chrome/browser/ui/cocoa/cocoa_test_helper.h"
#import "chrome/browser/ui/cocoa/wrench_menu/menu_tracked_root_view.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#import "third_party/ocmock/OCMock/OCMock.h"

class MenuTrackedRootViewTest : public CocoaTest {
 public:
  void SetUp() {
    CocoaTest::SetUp();
    view_.reset([[MenuTrackedRootView alloc] init]);
  }

  scoped_nsobject<MenuTrackedRootView> view_;
};

TEST_F(MenuTrackedRootViewTest, MouseUp) {
  id menu = [OCMockObject mockForClass:[NSMenu class]];
  [[menu expect] cancelTracking];

  id menuItem = [OCMockObject mockForClass:[NSMenuItem class]];
  [[[menuItem stub] andReturn:menu] menu];

  [view_ setMenuItem:menuItem];
  NSEvent* event = [NSEvent mouseEventWithType:NSLeftMouseUp
                                      location:NSMakePoint(42, 42)
                                 modifierFlags:0
                                     timestamp:0
                                  windowNumber:[test_window() windowNumber]
                                       context:nil
                                   eventNumber:1
                                    clickCount:1
                                      pressure:1.0];
  [view_ mouseUp:event];

  [menu verify];
  [menuItem verify];
}
