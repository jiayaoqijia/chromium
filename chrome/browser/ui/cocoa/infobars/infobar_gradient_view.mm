// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/cocoa/infobars/infobar_gradient_view.h"

#include "base/scoped_nsobject.h"
#import "chrome/browser/themes/browser_theme_provider.h"
#import "chrome/browser/ui/cocoa/infobars/infobar_container_controller.h"
#import "chrome/browser/ui/cocoa/themed_window.h"

namespace {

const double kBackgroundColorTop[3] =
    {255.0 / 255.0, 242.0 / 255.0, 183.0 / 255.0};
const double kBackgroundColorBottom[3] =
    {250.0 / 255.0, 230.0 / 255.0, 145.0 / 255.0};
}

@implementation InfoBarGradientView

- (id)initWithFrame:(NSRect)frameRect {
  if ((self = [super initWithFrame:frameRect])) {
    NSColor* startingColor =
        [NSColor colorWithCalibratedRed:kBackgroundColorTop[0]
                                  green:kBackgroundColorTop[1]
                                   blue:kBackgroundColorTop[2]
                                  alpha:1.0];
    NSColor* endingColor =
        [NSColor colorWithCalibratedRed:kBackgroundColorBottom[0]
                                  green:kBackgroundColorBottom[1]
                                   blue:kBackgroundColorBottom[2]
                                  alpha:1.0];
    scoped_nsobject<NSGradient> gradient(
        [[NSGradient alloc] initWithStartingColor:startingColor
                                       endingColor:endingColor]);
    [self setGradient:gradient];
  }
  return self;
}

- (NSColor*)strokeColor {
  ui::ThemeProvider* themeProvider = [[self window] themeProvider];
  if (!themeProvider)
    return [NSColor blackColor];

  BOOL active = [[self window] isMainWindow];
  return themeProvider->GetNSColor(
      active ? BrowserThemeProvider::COLOR_TOOLBAR_STROKE :
               BrowserThemeProvider::COLOR_TOOLBAR_STROKE_INACTIVE,
      true);
}

- (void)drawRect:(NSRect)rect {
  NSRect bounds = [self bounds];
  bounds.size.height -= infobars::kAntiSpoofHeight;

  const CGFloat tipHeight = infobars::kAntiSpoofHeight;
  const CGFloat curveDistance = 13.0;
  const CGFloat iconWidth = 29.0;
  const CGFloat tipPadding = 4.0;

  // Draw the tab bulge that acts as the anti-spoofing countermeasure.
  NSBezierPath* bulgePath = [NSBezierPath bezierPath];
  NSPoint startPoint = NSMakePoint(0, NSMaxY([self frame]) - tipHeight);
  [bulgePath moveToPoint:startPoint];
  [bulgePath relativeCurveToPoint:NSMakePoint(curveDistance, tipHeight)
                    // Fuzz the points by 0.5 pixels to get perfect alignment.
                    controlPoint1:NSMakePoint(curveDistance/2, 0.5)
                    controlPoint2:NSMakePoint(curveDistance/2,
                                              tipHeight - 0.5)];

  // The height is too small and the control points too close for the stroke
  // across this straight line to have enough definition. Save off the points
  // for later to create a separate line to stroke.
  NSPoint topStrokeStart = [bulgePath currentPoint];
  [bulgePath relativeLineToPoint:NSMakePoint(tipPadding + iconWidth, 0)];
  NSPoint topStrokeEnd = [bulgePath currentPoint];

  [bulgePath relativeCurveToPoint:NSMakePoint(curveDistance, -tipHeight)
                    // Fuzz the points by 0.5 pixels to get perfect alignment.
                    controlPoint1:NSMakePoint(curveDistance/2, 0.5)
                    controlPoint2:NSMakePoint(curveDistance/2,
                                              -tipHeight + 0.5)];

  // Around the bounds of the infobar, continue drawing the path into which the
  // gradient will be drawn.
  scoped_nsobject<NSBezierPath> infoBarPath([bulgePath copy]);
  [infoBarPath lineToPoint:NSMakePoint(NSMaxX(bounds), startPoint.y)];
  [infoBarPath lineToPoint:NSMakePoint(NSMaxX(bounds), NSMinY(bounds))];
  [infoBarPath lineToPoint:NSMakePoint(NSMinX(bounds), NSMinY(bounds))];
  [infoBarPath lineToPoint:NSMakePoint(NSMinX(bounds), startPoint.y)];
  [infoBarPath lineToPoint:startPoint];
  [infoBarPath closePath];

  // Draw the gradient.
  [[self gradient] drawInBezierPath:infoBarPath angle:270];

  // Stroke the bottom.
  NSColor* strokeColor = [self strokeColor];
  if (strokeColor) {
    [[self strokeColor] set];
    NSRect borderRect, contentRect;
    NSDivideRect(bounds, &borderRect, &contentRect, 1, NSMinYEdge);
    NSRectFillUsingOperation(borderRect, NSCompositeSourceOver);
  }

  // Stroke the bulge.
  [[self strokeColor] setStroke];
  [bulgePath setLineCapStyle:NSSquareLineCapStyle];
  [bulgePath stroke];

  // Stroke the horizontal line to ensure it has enough definition.
  --topStrokeStart.x;
  ++topStrokeEnd.x;
  NSBezierPath* topStroke = [NSBezierPath bezierPath];
  [topStroke moveToPoint:topStrokeStart];
  [topStroke lineToPoint:topStrokeEnd];
  [topStroke stroke];
}

- (BOOL)mouseDownCanMoveWindow {
  return NO;
}

// This view is intentionally not opaque because it overlaps with the findbar.

- (BOOL)accessibilityIsIgnored {
  return NO;
}

- (id)accessibilityAttributeValue:(NSString*)attribute {
  if ([attribute isEqual:NSAccessibilityRoleAttribute])
    return NSAccessibilityGroupRole;

  return [super accessibilityAttributeValue:attribute];
}

@end
