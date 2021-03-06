// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/file_util.h"
#include "base/message_loop.h"
#include "base/scoped_temp_dir.h"
#include "base/string_number_conversions.h"
#include "chrome/browser/browser_thread.h"
#include "chrome/browser/download/base_file.h"
#include "net/base/file_stream.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

const char kTestData1[] = "Let's write some data to the file!\n";
const char kTestData2[] = "Writing more data.\n";
const char kTestData3[] = "Final line.";

class BaseFileTest : public testing::Test {
 public:
  BaseFileTest() : file_thread_(BrowserThread::FILE, &message_loop_) {
  }

  virtual void SetUp() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_file_.reset(
        new BaseFile(FilePath(), GURL(), GURL(), 0, file_stream_));
  }

  virtual void TearDown() {
    EXPECT_FALSE(base_file_->in_progress());
    EXPECT_EQ(static_cast<int64>(expected_data_.size()),
              base_file_->bytes_so_far());

    if (!expected_data_.empty()) {
      // Make sure the data has been properly written to disk.
      std::string disk_data;
      EXPECT_TRUE(file_util::ReadFileToString(base_file_->full_path(),
                                              &disk_data));
      EXPECT_EQ(expected_data_, disk_data);
    }

    // Make sure the mock BrowserThread outlives the BaseFile to satisfy
    // thread checks inside it.
    base_file_.reset();
  }

  void AppendDataToFile(const std::string& data) {
    ASSERT_TRUE(base_file_->in_progress());
    base_file_->AppendDataToFile(data.data(), data.size());
    expected_data_ += data;
    EXPECT_EQ(static_cast<int64>(expected_data_.size()),
              base_file_->bytes_so_far());
  }

 protected:
  linked_ptr<net::FileStream> file_stream_;

  // BaseClass instance we are testing.
  scoped_ptr<BaseFile> base_file_;

  // Temporary directory for renamed downloads.
  ScopedTempDir temp_dir_;

 private:
  // Keep track of what data should be saved to the disk file.
  std::string expected_data_;

  // Mock file thread to satisfy debug checks in BaseFile.
  MessageLoop message_loop_;
  BrowserThread file_thread_;
};

// Test the most basic scenario: just create the object and do a sanity check
// on all its accessors. This is actually a case that rarely happens
// in production, where we would at least Initialize it.
TEST_F(BaseFileTest, CreateDestroy) {
  EXPECT_EQ(FilePath().value(), base_file_->full_path().value());
  EXPECT_FALSE(base_file_->path_renamed());
}

// Cancel the download explicitly.
TEST_F(BaseFileTest, Cancel) {
  ASSERT_TRUE(base_file_->Initialize(false));
  EXPECT_TRUE(file_util::PathExists(base_file_->full_path()));
  base_file_->Cancel();
  EXPECT_FALSE(file_util::PathExists(base_file_->full_path()));
  EXPECT_NE(FilePath().value(), base_file_->full_path().value());
  EXPECT_FALSE(base_file_->path_renamed());
}

// Write data to the file once.
TEST_F(BaseFileTest, SingleWrite) {
  ASSERT_TRUE(base_file_->Initialize(false));
  AppendDataToFile(kTestData1);
  base_file_->Finish();

  EXPECT_FALSE(base_file_->path_renamed());
}

// Write data to the file multiple times.
TEST_F(BaseFileTest, MultipleWrites) {
  ASSERT_TRUE(base_file_->Initialize(false));
  AppendDataToFile(kTestData1);
  AppendDataToFile(kTestData2);
  AppendDataToFile(kTestData3);
  std::string hash;
  EXPECT_FALSE(base_file_->GetSha256Hash(&hash));
  base_file_->Finish();

  EXPECT_FALSE(base_file_->path_renamed());
}

// Write data to the file once and calculate its sha256 hash.
TEST_F(BaseFileTest, SingleWriteWithHash) {
  ASSERT_TRUE(base_file_->Initialize(true));
  AppendDataToFile(kTestData1);
  base_file_->Finish();

  EXPECT_FALSE(base_file_->path_renamed());

  std::string hash;
  base_file_->GetSha256Hash(&hash);
  EXPECT_EQ("0B2D3F3F7943AD64B860DF94D05CB56A8A97C6EC5768B5B70B930C5AA7FA9ADE",
            base::HexEncode(hash.data(), hash.size()));
}

// Write data to the file multiple times and calculate its sha256 hash.
TEST_F(BaseFileTest, MultipleWritesWithHash) {
  std::string hash;

  ASSERT_TRUE(base_file_->Initialize(true));
  AppendDataToFile(kTestData1);
  AppendDataToFile(kTestData2);
  AppendDataToFile(kTestData3);
  // no hash before Finish() is called either.
  EXPECT_FALSE(base_file_->GetSha256Hash(&hash));
  base_file_->Finish();

  EXPECT_FALSE(base_file_->path_renamed());
  EXPECT_TRUE(base_file_->GetSha256Hash(&hash));
  EXPECT_EQ("CBF68BF10F8003DB86B31343AFAC8C7175BD03FB5FC905650F8C80AF087443A8",
            base::HexEncode(hash.data(), hash.size()));
}

// Rename the file after all writes to it.
TEST_F(BaseFileTest, WriteThenRename) {
  ASSERT_TRUE(base_file_->Initialize(false));

  FilePath initial_path(base_file_->full_path());
  EXPECT_TRUE(file_util::PathExists(initial_path));
  FilePath new_path(temp_dir_.path().AppendASCII("NewFile"));
  EXPECT_FALSE(file_util::PathExists(new_path));

  AppendDataToFile(kTestData1);

  EXPECT_TRUE(base_file_->Rename(new_path, true));
  EXPECT_FALSE(file_util::PathExists(initial_path));
  EXPECT_TRUE(file_util::PathExists(new_path));

  base_file_->Finish();

  EXPECT_TRUE(base_file_->path_renamed());
}

// Rename the file while the download is still in progress.
TEST_F(BaseFileTest, RenameWhileInProgress) {
  ASSERT_TRUE(base_file_->Initialize(false));

  FilePath initial_path(base_file_->full_path());
  EXPECT_TRUE(file_util::PathExists(initial_path));
  FilePath new_path(temp_dir_.path().AppendASCII("NewFile"));
  EXPECT_FALSE(file_util::PathExists(new_path));

  AppendDataToFile(kTestData1);

  EXPECT_TRUE(base_file_->in_progress());
  EXPECT_TRUE(base_file_->Rename(new_path, true));
  EXPECT_FALSE(file_util::PathExists(initial_path));
  EXPECT_TRUE(file_util::PathExists(new_path));

  AppendDataToFile(kTestData2);

  base_file_->Finish();

  EXPECT_TRUE(base_file_->path_renamed());
}

}  // namespace
