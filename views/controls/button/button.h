// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIEWS_CONTROLS_BUTTON_BUTTON_H_
#define VIEWS_CONTROLS_BUTTON_BUTTON_H_
#pragma once

#include "views/view.h"

namespace views {

class Button;
class Event;

// An interface implemented by an object to let it know that a button was
// pressed.
class ButtonListener {
 public:
  virtual void ButtonPressed(Button* sender, const views::Event& event) = 0;

 protected:
  virtual ~ButtonListener() {}
};

// A View representing a button. Depending on the specific type, the button
// could be implemented by a native control or custom rendered.
class Button : public View {
 public:
  virtual ~Button();

  void SetTooltipText(const std::wstring& tooltip_text);

  int tag() const { return tag_; }
  void set_tag(int tag) { tag_ = tag; }

  int mouse_event_flags() const { return mouse_event_flags_; }

  void SetAccessibleKeyboardShortcut(const std::wstring& shortcut);

  // Overridden from View:
  virtual bool GetTooltipText(const gfx::Point& p,
                              std::wstring* tooltip) OVERRIDE;
  virtual string16 GetAccessibleKeyboardShortcut() OVERRIDE;
  virtual AccessibilityTypes::Role GetAccessibleRole() OVERRIDE;

 protected:
  // Construct the Button with a Listener. The listener can be NULL. This can be
  // true of buttons that don't have a listener - e.g. menubuttons where there's
  // no default action and checkboxes.
  explicit Button(ButtonListener* listener);

  // Cause the button to notify the listener that a click occurred.
  virtual void NotifyClick(const views::Event& event);

  // The button's listener. Notified when clicked.
  ButtonListener* listener_;

 private:
  // The text shown in a tooltip.
  string16 tooltip_text_;

  // Accessibility data.
  string16 accessible_shortcut_;

  // The id tag associated with this button. Used to disambiguate buttons in
  // the ButtonListener implementation.
  int tag_;

  // Event flags present when the button was clicked.
  int mouse_event_flags_;

  DISALLOW_COPY_AND_ASSIGN(Button);
};

}  // namespace views

#endif  // VIEWS_CONTROLS_BUTTON_BUTTON_H_
