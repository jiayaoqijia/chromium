// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/tls_client_login_cache.h"

#include "base/time.h"
#include "base/utf_string_conversions.h"
#include "net/base/auth.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(TLSClientLoginCacheTest, LookupAddRemove) {
  TLSClientLoginCache cache;

  std::string server1("foo1:443");
  scoped_refptr<AuthData> auth_data1(new AuthData);
  auth_data1->username = ASCIIToUTF16("user1");
  auth_data1->password = ASCIIToUTF16("secret1");

  std::string server2("foo2:443");
  scoped_refptr<AuthData> auth_data2(new AuthData);
  auth_data2->username = ASCIIToUTF16("user2");
  auth_data2->password = ASCIIToUTF16("secret2");

  std::string server3("foo3:443");
  scoped_refptr<AuthData> auth_data3(new AuthData);
  auth_data3->username = ASCIIToUTF16("user3");
  auth_data3->password = ASCIIToUTF16("secret3");

  scoped_refptr<AuthData> cached_auth_data;
  // Lookup non-existent TLS login credentials.
  cached_auth_data = NULL;
  EXPECT_FALSE(cache.Lookup(server1, &cached_auth_data));

  // Add TLS login credentials for server1.
  cache.Add(server1, auth_data1);
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server1, &cached_auth_data));
  EXPECT_EQ(auth_data1, cached_auth_data);

  // Add TLS login credentials for server2.
  cache.Add(server2, auth_data2);
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server1, &cached_auth_data));
  EXPECT_EQ(auth_data1, cached_auth_data.get());
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server2, &cached_auth_data));
  EXPECT_EQ(auth_data2, cached_auth_data);

  // Overwrite the TLS login credentials for server1.
  cache.Add(server1, auth_data3);
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server1, &cached_auth_data));
  EXPECT_EQ(auth_data3, cached_auth_data);
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server2, &cached_auth_data));
  EXPECT_EQ(auth_data2, cached_auth_data);

  // Remove TLS login credentials of server1.
  cache.Remove(server1);
  cached_auth_data = NULL;
  EXPECT_FALSE(cache.Lookup(server1, &cached_auth_data));
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server2, &cached_auth_data));
  EXPECT_EQ(auth_data2, cached_auth_data);

  // Remove non-existent TLS login credentials.
  cache.Remove(server1);
  cached_auth_data = NULL;
  EXPECT_FALSE(cache.Lookup(server1, &cached_auth_data));
  cached_auth_data = NULL;
  EXPECT_TRUE(cache.Lookup(server2, &cached_auth_data));
  EXPECT_EQ(auth_data2, cached_auth_data);
}

// Check that if the server differs only by port number, it is considered
// a separate server.
TEST(TLSClientLoginCacheTest, LookupWithPort) {
  TLSClientLoginCache cache;

  std::string server1("foo1:443");
  scoped_refptr<AuthData> auth_data1(new AuthData);
  auth_data1->username = ASCIIToUTF16("user1");
  auth_data1->password = ASCIIToUTF16("secret1");

  std::string server2("foo2:8443");
  scoped_refptr<AuthData> auth_data2(new AuthData);
  auth_data2->username = ASCIIToUTF16("user2");
  auth_data2->password = ASCIIToUTF16("secret2");

  cache.Add(server1, auth_data1.get());
  cache.Add(server2, auth_data2.get());

  scoped_refptr<AuthData> cached_auth_data;
  EXPECT_TRUE(cache.Lookup(server1, &cached_auth_data));
  EXPECT_EQ(auth_data1.get(), cached_auth_data);
  EXPECT_TRUE(cache.Lookup(server2, &cached_auth_data));
  EXPECT_EQ(auth_data2.get(), cached_auth_data);
}

}  // namespace net
