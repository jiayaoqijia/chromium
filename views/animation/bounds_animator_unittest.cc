// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "ui/base/animation/slide_animation.h"
#include "ui/base/animation/test_animation_delegate.h"
#include "views/animation/bounds_animator.h"
#include "views/view.h"

using views::BoundsAnimator;
using ui::Animation;
using ui::SlideAnimation;
using ui::TestAnimationDelegate;

namespace {

class TestBoundsAnimator : public BoundsAnimator {
 public:
  explicit TestBoundsAnimator(views::View* view) : BoundsAnimator(view) {
  }

 protected:
  SlideAnimation* CreateAnimation() {
    SlideAnimation* animation = BoundsAnimator::CreateAnimation();
    animation->SetSlideDuration(10);
    return animation;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(TestBoundsAnimator);
};

class OwnedDelegate : public BoundsAnimator::OwnedAnimationDelegate {
 public:
  OwnedDelegate() {
    deleted_ = false;
    canceled_ = false;
  }

  ~OwnedDelegate() {
    deleted_ = true;
  }

  static bool get_and_clear_deleted() {
    bool value = deleted_;
    deleted_ = false;
    return value;
  }

  static bool get_and_clear_canceled() {
    bool value = canceled_;
    canceled_ = false;
    return value;
  }

  // AnimationDelegate:
  virtual void AnimationCanceled(const Animation* animation) {
    canceled_ = true;
  }

 private:
  static bool deleted_;
  static bool canceled_;

  DISALLOW_COPY_AND_ASSIGN(OwnedDelegate);
};

// static
bool OwnedDelegate::deleted_ = false;

// static
bool OwnedDelegate::canceled_ = false;

class TestView : public views::View {
 public:
  TestView() {}
  virtual void SchedulePaint(const gfx::Rect& r, bool urgent) {
    if (dirty_rect_.IsEmpty())
      dirty_rect_ = r;
    else
      dirty_rect_ = dirty_rect_.Union(r);
  }

  const gfx::Rect& dirty_rect() const { return dirty_rect_; }

 private:
  gfx::Rect dirty_rect_;

  DISALLOW_COPY_AND_ASSIGN(TestView);
};

}  // namespace

class BoundsAnimatorTest : public testing::Test {
 public:
  BoundsAnimatorTest() : child_(new TestView()), animator_(&parent_) {
    parent_.AddChildView(child_);
  }

  TestView* parent() { return &parent_; }
  TestView* child() { return child_; }
  TestBoundsAnimator* animator() { return &animator_; }

 private:
  MessageLoopForUI message_loop_;
  TestView parent_;
  TestView* child_;  // Owned by |parent_|.
  TestBoundsAnimator animator_;

  DISALLOW_COPY_AND_ASSIGN(BoundsAnimatorTest);
};

// Checks animate view to.
TEST_F(BoundsAnimatorTest, AnimateViewTo) {
  TestAnimationDelegate delegate;
  gfx::Rect initial_bounds(0, 0, 10, 10);
  child()->SetBounds(initial_bounds);
  gfx::Rect target_bounds(10, 10, 20, 20);
  animator()->AnimateViewTo(child(), target_bounds);
  animator()->SetAnimationDelegate(child(), &delegate, false);

  // The animator should be animating now.
  EXPECT_TRUE(animator()->IsAnimating());

  // Run the message loop; the delegate exits the loop when the animation is
  // done.
  MessageLoop::current()->Run();

  // Make sure the bounds match of the view that was animated match.
  EXPECT_EQ(target_bounds, child()->bounds());

  // The parent should have been told to repaint as the animation progressed.
  // The resulting rect is the union of the original and target bounds.
  EXPECT_EQ(target_bounds.Union(initial_bounds), parent()->dirty_rect());
}

// Make sure an AnimationDelegate is deleted when canceled.
TEST_F(BoundsAnimatorTest, DeleteDelegateOnCancel) {
  animator()->AnimateViewTo(child(), gfx::Rect(0, 0, 10, 10));
  animator()->SetAnimationDelegate(child(), new OwnedDelegate(), true);

  animator()->Cancel();

  // The animator should no longer be animating.
  EXPECT_FALSE(animator()->IsAnimating());

  // The cancel should both cancel the delegate and delete it.
  EXPECT_TRUE(OwnedDelegate::get_and_clear_canceled());
  EXPECT_TRUE(OwnedDelegate::get_and_clear_deleted());
}

// Make sure an AnimationDelegate is deleted when another animation is
// scheduled.
TEST_F(BoundsAnimatorTest, DeleteDelegateOnNewAnimate) {
  animator()->AnimateViewTo(child(), gfx::Rect(0, 0, 10, 10));
  animator()->SetAnimationDelegate(child(), new OwnedDelegate(), true);

  animator()->AnimateViewTo(child(), gfx::Rect(0, 0, 10, 10));

  // Starting a new animation should both cancel the delegate and delete it.
  EXPECT_TRUE(OwnedDelegate::get_and_clear_deleted());
  EXPECT_TRUE(OwnedDelegate::get_and_clear_canceled());
}

// Makes sure StopAnimating works.
TEST_F(BoundsAnimatorTest, StopAnimating) {
  scoped_ptr<OwnedDelegate> delegate(new OwnedDelegate());

  animator()->AnimateViewTo(child(), gfx::Rect(0, 0, 10, 10));
  animator()->SetAnimationDelegate(child(), new OwnedDelegate(), true);

  animator()->StopAnimatingView(child());

  // Shouldn't be animating now.
  EXPECT_FALSE(animator()->IsAnimating());

  // Stopping should both cancel the delegate and delete it.
  EXPECT_TRUE(OwnedDelegate::get_and_clear_deleted());
  EXPECT_TRUE(OwnedDelegate::get_and_clear_canceled());
}
