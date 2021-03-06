// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/webdata/autofill_change.h"

#include "chrome/browser/autofill/autofill_profile.h"
#include "chrome/browser/autofill/credit_card.h"

AutofillChange::AutofillChange(Type type, const AutofillKey& key)
    : GenericAutofillChange<AutofillKey>(type, key) {
}

AutofillChange::~AutofillChange() {
}

AutofillProfileChange::AutofillProfileChange(Type type,
                                             string16 key,
                                             const AutoFillProfile* profile,
                                             const string16& pre_update_label)
    : GenericAutofillChange<string16>(type, key),
      profile_(profile),
      pre_update_label_(pre_update_label) {
}

AutofillProfileChange::~AutofillProfileChange() {
}

bool AutofillProfileChange::operator==(
    const AutofillProfileChange& change) const {
  if (type() != change.type() || key() != change.key())
    return false;
  if (type() == REMOVE)
    return true;
  if (*profile() != *change.profile())
    return false;
  return type() == ADD || pre_update_label_ == change.pre_update_label();
}

AutofillCreditCardChange::AutofillCreditCardChange(
  Type type, string16 key, const CreditCard* credit_card)
    : GenericAutofillChange<string16>(type, key), credit_card_(credit_card) {
}

AutofillCreditCardChange::~AutofillCreditCardChange() {
}

bool AutofillCreditCardChange::operator==(
    const AutofillCreditCardChange& change) const {
  return type() == change.type() &&
         key() == change.key() &&
         (type() != REMOVE) ? *credit_card() == *change.credit_card() : true;
}

AutofillProfileChangeGUID::AutofillProfileChangeGUID(
  Type type, std::string key, const AutoFillProfile* profile)
    : GenericAutofillChange<std::string>(type, key),
      profile_(profile) {
  DCHECK(type == ADD ? (profile && profile->guid() == key) : true);
  DCHECK(type == UPDATE ? (profile && profile->guid() == key) : true);
  DCHECK(type == REMOVE ? !profile : true);
}

AutofillProfileChangeGUID::~AutofillProfileChangeGUID() {
}

bool AutofillProfileChangeGUID::operator==(
    const AutofillProfileChangeGUID& change) const {
  return type() == change.type() &&
         key() == change.key() &&
         (type() != REMOVE) ? *profile() == *change.profile() : true;
}

AutofillCreditCardChangeGUID::AutofillCreditCardChangeGUID(
  Type type, std::string key, const CreditCard* credit_card)
    : GenericAutofillChange<std::string>(type, key), credit_card_(credit_card) {
  DCHECK(type == ADD ? (credit_card && credit_card->guid() == key) : true);
  DCHECK(type == UPDATE ? (credit_card && credit_card->guid() == key) : true);
  DCHECK(type == REMOVE ? !credit_card : true);
}

AutofillCreditCardChangeGUID::~AutofillCreditCardChangeGUID() {
}

bool AutofillCreditCardChangeGUID::operator==(
    const AutofillCreditCardChangeGUID& change) const {
  return type() == change.type() &&
         key() == change.key() &&
         (type() != REMOVE) ? *credit_card() == *change.credit_card() : true;
}
