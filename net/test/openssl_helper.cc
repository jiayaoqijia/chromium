// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This helper binary is only used for testing Chrome's SSL stack.

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/srp.h>

static const char kDefaultPEMFile[] = "net/data/ssl/certificates/ok_cert.pem";
static const char kDefaultSRPVFile[] = "net/data/ssl/certificates/ok.srpv";

// Server Name Indication callback from OpenSSL
static int sni_cb(SSL *s, int *ad, void *arg) {
  const char* servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
  if (servername && strcmp(servername, "test.example.com") == 0)
    *reinterpret_cast<bool*>(arg) = true;

  return SSL_TLSEXT_ERR_OK;
}

// Client certificate verification callback from OpenSSL
static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  return preverify_ok;
}

// Next Protocol Negotiation callback from OpenSSL
static int next_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned int *outlen, void *arg) {
  bool* npn_mispredict = reinterpret_cast<bool*>(arg);
  static char kProtos[] = "\003foo\003bar";
  static char kProtos2[] = "\003baz\003boo";
  static unsigned count = 0;

  if (!*npn_mispredict || count == 0) {
    *out = (const unsigned char*) kProtos;
    *outlen = sizeof(kProtos) - 1;
  } else {
    *out = (const unsigned char*) kProtos2;
    *outlen = sizeof(kProtos2) - 1;
  }
  count++;
  return SSL_TLSEXT_ERR_OK;
}

// This is a context that we pass to callbacks
// (from openssl/apps/s_server.c)
typedef struct srpsrvparm_st {
  int verbose;
  char *login;
  SRP_VBASE *vb;
} srpsrvparm;

// (from openssl/apps/s_server.c)
static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg) {
  srpsrvparm * p = (srpsrvparm *) arg;
  SRP_user_pwd *user;
  int rv;

  p->login = BUF_strdup(SSL_get_srp_username(s));
  fprintf(stderr,"SRP username = \"%s\"\n",p->login);

  user = SRP_VBASE_get_by_user(p->vb, p->login);	
  if (user == NULL) {
    fprintf(stderr, "User %s doesn't exist\n", p->login);
    return SSL3_AL_FATAL;
  }

  /* TODO(sqs): see why it expects non-const BIGNUM* */
  rv = SSL_set_srp_server_param(s, (BIGNUM*)user->N, (BIGNUM*)user->g, 
                                user->s, user->v, user->info);
  if (rv < 0) {
    *ad = SSL_AD_INTERNAL_ERROR;
    return SSL3_AL_FATAL;
  }
  return SSL_ERROR_NONE;
}

int
main(int argc, char **argv) {
  SSL_library_init();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  bool sni = false, sni_good = false, snap_start = false;
  bool snap_start_recovery = false, sslv3 = false, session_tickets = false;
  bool fail_resume = false, client_cert = false, npn = false;
  bool npn_mispredict = false, tlssrp = false, open_socket = false;

  unsigned short listen_port = 4443;

  const char* key_file = kDefaultPEMFile;
  const char* cert_file = kDefaultPEMFile;
  const char* srpv_file = kDefaultSRPVFile;

  srpsrvparm srpp;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "sni") == 0) {
      // Require SNI
      sni = true;
    } else if (strcmp(argv[i], "snap-start") == 0) {
      // Support Snap Start
      snap_start = true;
    } else if (strcmp(argv[i], "snap-start-recovery") == 0) {
      // Support Snap Start, but always trigger a recovery
      snap_start = true;
      snap_start_recovery = true;
    } else if (strcmp(argv[i], "sslv3") == 0) {
      // Use SSLv3
      sslv3 = true;
      if (tlssrp) {
        fprintf(stderr, "TLS-SRP requires TLSv1; do not use sslv3 option\n");
        return 1;
      }
    } else if (strcmp(argv[i], "session-tickets") == 0) {
      // Enable Session Tickets
      session_tickets = true;
    } else if (strcmp(argv[i], "fail-resume") == 0) {
      // Always fail to resume sessions
      fail_resume = true;
    } else if (strcmp(argv[i], "client-cert") == 0) {
      // Request a client certificate
      client_cert = true;
    } else if (strcmp(argv[i], "npn") == 0) {
      // Advertise NPN
      npn = true;
    } else if (strcmp(argv[i], "npn-mispredict") == 0) {
      // Advertise NPN
      npn = true;
      npn_mispredict = true;
    } else if (strcmp(argv[i], "open-socket") == 0) {
      open_socket = true;
    } else if (strcmp(argv[i], "tls-srp") == 0) {
      tlssrp = true;
      if (sslv3) {
        fprintf(stderr, "TLS-SRP requires TLSv1; do not use sslv3 option\n");
        return 1;
      }
    } else if (strcmp(argv[i], "--key-file") == 0) {
      // Use alternative key file
      i++;
      if (i == argc) {
        fprintf(stderr, "Missing argument to --key-file\n");
        return 1;
      }
      key_file = argv[i];
    } else if (strcmp(argv[i], "--cert-file") == 0) {
      // Use alternative certificate file
      i++;
      if (i == argc) {
        fprintf(stderr, "Missing argument to --cert-file\n");
        return 1;
      }
      cert_file = argv[i];
    } else if (strcmp(argv[i], "--srpv-file") == 0) {
      i++;
      if (i == argc) {
        fprintf(stderr, "Missing argument to --srpv-file\n");
        return 1;
      }
      srpv_file = argv[i];
    } else if (strcmp(argv[i], "--port") == 0) {
      i++;
      if (i == argc) {
        fprintf(stderr, "Missing argument to --port\n");
        return 1;
      }
      listen_port = (unsigned short)atoi(argv[i]);
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 1;
    }
  }

  SSL_CTX* ctx;

  if (sslv3) {
    ctx = SSL_CTX_new(SSLv3_server_method());
  } else {
    ctx = SSL_CTX_new(TLSv1_server_method());
  }

  if (sni) {
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, &sni_good);
  }

  if (!tlssrp) {
    BIO* key = BIO_new(BIO_s_file());
    if (BIO_read_filename(key, key_file) <= 0) {
      fprintf(stderr, "Failed to read %s\n", key_file);
      return 1;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    if (!pkey) {
      fprintf(stderr, "Failed to parse %s\n", key_file);
      return 1;
    }
    BIO_free(key);


    BIO* cert = BIO_new(BIO_s_file());
    if (BIO_read_filename(cert, cert_file) <= 0) {
      fprintf(stderr, "Failed to read %s\n", cert_file);
      return 1;
    }

    X509 *pcert = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if (!pcert) {
      fprintf(stderr, "Failed to parse %s\n", cert_file);
      return 1;
    }
    BIO_free(cert);

    if (SSL_CTX_use_certificate(ctx, pcert) <= 0) {
      fprintf(stderr, "Failed to load %s\n", cert_file);
      return 1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
      fprintf(stderr, "Failed to load %s\n", key_file);
      return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
      fprintf(stderr, "Public and private keys don't match\n");
      return 1;
    }

    if (client_cert)
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
  }

  if (session_tickets)
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

  if (snap_start) {
    static const unsigned char orbit[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    SSL_CTX_set_snap_start_orbit(ctx, orbit);
  }

  if (npn)
    SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb, &npn_mispredict);

  if (tlssrp) {
    srpp.vb = SRP_VBASE_new(NULL);
    if (SRP_VBASE_init(srpp.vb, (char *)srpv_file) != SRP_NO_ERROR) {
      fprintf(stderr, "Failed to load SRP verifier file %s\n", srpv_file);
      return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_cb);
    SSL_CTX_set_srp_cb_arg(ctx, &srpp);  			
    SSL_CTX_set_srp_username_callback(ctx, ssl_srp_server_param_cb);
    fprintf(stderr, "Using SRP verifier file %s\n", srpv_file);
  }

  unsigned connection_limit = 1;
  if (snap_start || session_tickets)
    connection_limit = 2;
  if (npn_mispredict)
    connection_limit = 3;

  for (unsigned connections = 0; connections < connection_limit;
       connections++) {
    int listener = 3; /* default to using parent process' fd 3 */

    if (open_socket) {
      listener = socket(AF_INET, SOCK_STREAM, 0);
      if (listener < 0) {
        fprintf(stderr, "Failed to open socket\n");
        return 1;
      }

      struct sockaddr_in sin;
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_port = htons((unsigned short)listen_port);
      if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "Failed to bind socket\n");
        return 1;
      }

      if (listen(listener, 1) != 0) {
        fprintf(stderr, "Failed to listen on socket\n");
        return 1;
      }

      fprintf(stderr, "Listening on localhost:%d\n", listen_port);
    }

    const int fd = accept(listener, NULL, NULL);

    SSL* server = SSL_new(ctx);
    BIO* bio = BIO_new_socket(fd, 1 /* take ownership of fd */);
    SSL_set_bio(server, bio, bio);

    if (fail_resume) {
      SSL_set_session_id_context(server, (unsigned char*) &connections,
                                 sizeof(connections));
    }

    int err;
    for (;;) {
      const int ret = SSL_accept(server);
      if (ret == 1)
        break;

      err = SSL_get_error(server, ret);
      if (err == SSL_ERROR_WANT_READ)
        continue;
      if (err == SSL_ERROR_SERVER_RANDOM_VALIDATION_PENDING && snap_start) {
        SSL_set_suggested_server_random_validity(
            server, !snap_start_recovery);
        continue;
      }
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "SSL_accept failed: %d\n", err);
      return 1;
    }

    if (sni && !sni_good) {
      fprintf(stderr, "SNI failed\n");
      return 1;
    }

    if (npn) {
      const unsigned char *data, *expected_data;
      unsigned len, expected_len;
      SSL_get0_next_proto_negotiated(server, &data, &len);
      if (!npn_mispredict || connections == 0) {
        expected_data = (unsigned char*) "foo";
        expected_len = 3;
      } else {
        expected_data = (unsigned char*) "baz";
        expected_len = 3;
      }
      if (len != expected_len || memcmp(data, expected_data, len) != 0) {
        fprintf(stderr, "Bad NPN: %d\n", len);
        return 1;
      }
    }

    unsigned char buffer[6];

    int ret = SSL_read(server, buffer, sizeof(buffer));
    if (ret == -1) {
      err = SSL_get_error(server, ret);
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "SSL_read failed: %d\n", err);
    }
    if (memcmp(buffer, "hello!", sizeof(buffer)) == 0) {
      SSL_write(server, "goodbye!", 8);
    } else if (memcmp(buffer, "whoami", sizeof(buffer)) == 0) {
      char *username = SSL_get_srp_username(server);
      if (username) {
        SSL_write(server, username, strlen(username));
      } else {
        SSL_write(server, "not-using-tls-srp", 17);
      }
    }

    SSL_shutdown(server);
    SSL_shutdown(server);
    close(fd);
  }

  SSL_CTX_free(ctx);

  return 0;
}
