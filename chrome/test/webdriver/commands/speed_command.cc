// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/utf_string_conversions.h"
#include "chrome/test/webdriver/commands/speed_command.h"

namespace webdriver {

bool SpeedCommand::Init(Response* const response) {
  std::string speed;

  if (!WebDriverCommand::Init(response)) {
    SET_WEBDRIVER_ERROR(response, "Failure on Init for setting speed",
                      kInternalServerError);
    return false;
  }

  // The speed parameter must be passed in as SLOW, MEDIUM, or FAST.
  // The command must also be in all upper case letters.
  if (!GetStringASCIIParameter("speed", &speed)) {
    SET_WEBDRIVER_ERROR(response, "Request missing speed parameter",
                        kBadRequest);
    return false;
  }

  if (speed.compare("SLOW") == 0) {
    LOG(INFO) << "Speed set to slow";
    speed_ = Session::kSlow;
  } else if (speed.compare("MEDIUM") == 0) {
    LOG(INFO) << "Speed set to medium";
    speed_ = Session::kMedium;
  } else if (speed.compare("FAST") == 0) {
    LOG(INFO) << "Speed set to fast" << std::endl;
    speed_ = Session::kFast;
  } else {
    // If the speed is invalid throw and error in the POST response.
    LOG(INFO) << "Requested an unknown speed: " << speed;
    speed_ = Session::kUnknown;
  }

  return true;
}

void SpeedCommand::ExecuteGet(Response* const response) {
  switch (session_->speed()) {
    case Session::kSlow:
      response->set_value(new StringValue("SLOW"));
      response->set_status(kSuccess);
      break;

    case Session::kMedium:
      response->set_value(new StringValue("MEDIUM"));
      response->set_status(kSuccess);
      break;

    case Session::kFast:
      response->set_value(new StringValue("FAST"));
      response->set_status(kSuccess);
      break;

    default:
      // The speed should have never been set to unknown.
      SET_WEBDRIVER_ERROR(response, "Unknown speed set",
                          kInternalServerError);
      NOTREACHED();
      break;
  }
}

void SpeedCommand::ExecutePost(Response* const response) {
  if (speed_ == Session::kUnknown) {
    SET_WEBDRIVER_ERROR(response, "Invalid speed requested",
                        kInternalServerError);
    return;
  }

  session_->set_speed(speed_);
  response->set_value(new StringValue("success"));
  response->set_status(kSuccess);
}

}  // namespace webdriver

