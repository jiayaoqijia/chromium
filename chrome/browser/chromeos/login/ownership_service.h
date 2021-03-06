// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_LOGIN_OWNERSHIP_SERVICE_H_
#define CHROME_BROWSER_CHROMEOS_LOGIN_OWNERSHIP_SERVICE_H_
#pragma once

#include <string>
#include <vector>

#include "chrome/browser/chromeos/login/owner_key_utils.h"
#include "chrome/browser/chromeos/login/owner_manager.h"

namespace base {
template <typename T> struct DefaultLazyInstanceTraits;
}

namespace chromeos {

class OwnershipService {
 public:
  // Returns the singleton instance of the OwnershipService.
  static OwnershipService* GetSharedInstance();
  virtual ~OwnershipService();

  virtual bool IsAlreadyOwned();

  // If the device has been owned already, posts a task to the FILE thread to
  // fetch the public key off disk.
  // Returns true if the attempt was initiated, false otherwise.
  //
  // Sends out a OWNER_KEY_FETCH_ATTEMPT_SUCCESS notification on success,
  // OWNER_KEY_FETCH_ATTEMPT_FAILED on failure.
  virtual bool StartLoadOwnerKeyAttempt();

  // If the device has not yet been owned, posts a task to the FILE
  // thread to generate the owner's keys and put them in the right
  // places.  Keeps them in memory as well, for later use.
  // Returns true if the attempt was initiated, false otherwise.
  //
  // Upon failure, sends out OWNER_KEY_FETCH_ATTEMPT_FAILED.
  // Upon success, sends out OWNER_KEY_FETCH_ATTEMPT_SUCCESS.
  // If no attempt is started (if the device is already owned), no
  // notification is sent.
  virtual bool StartTakeOwnershipAttempt(const std::string& owner);

  // Initiate an attempt to sign |data| with |private_key_|.  Will call
  // d->OnKeyOpComplete() when done.  Upon success, the signature will be passed
  // as the |payload| argument to d->OnKeyOpComplete().
  // Returns true if the attempt was initiated, false otherwise.
  //
  // If you call this on a well-known thread, you'll be called back on that
  // thread.  Otherwise, you'll get called back on the UI thread.
  virtual void StartSigningAttempt(const std::string& data,
                                   OwnerManager::Delegate* d);

  // Initiate an attempt to verify that |signature| is valid over |data| with
  // |public_key_|.  When the attempt is completed, an appropriate KeyOpCode
  // will be passed to d->OnKeyOpComplete().
  // Returns true if the attempt was initiated, false otherwise.
  //
  // If you call this on a well-known thread, you'll be called back on that
  // thread.  Otherwise, you'll get called back on the UI thread.
  virtual void StartVerifyAttempt(const std::string& data,
                                  const std::vector<uint8>& signature,
                                  OwnerManager::Delegate* d);

  virtual bool CurrentUserIsOwner();

 protected:
  OwnershipService();

 private:
  friend struct base::DefaultLazyInstanceTraits<OwnershipService>;
  friend class OwnershipServiceTest;

  scoped_refptr<OwnerManager> manager_;
  scoped_refptr<OwnerKeyUtils> utils_;
};

}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_LOGIN_OWNERSHIP_SERVICE_H_
