/*
 * gtlsdatabase-openssl.c
 *
 * Copyright (C) 2015 NICE s.r.l.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Authors: Ignacio Casal Quinteiro
 */

#include "config.h"

#include "gtlsdatabase-openssl.h"
#include "gtlscertificate-openssl.h"

#include <openssl/ssl.h>
#include <glib/gi18n-lib.h>

G_DEFINE_ABSTRACT_TYPE (GTlsDatabaseOpenssl, g_tls_database_openssl, G_TYPE_TLS_DATABASE)

enum {
  STATUS_FAILURE,
  STATUS_INCOMPLETE,
  STATUS_SELFSIGNED,
  STATUS_PINNED,
  STATUS_ANCHORED,
};

static gboolean
is_self_signed (GTlsCertificateOpenssl *certificate)
{
  X509 *cert;
  X509_STORE *store;
  X509_STORE_CTX csc;
  STACK_OF(X509) *trusted;
  gboolean ret = FALSE;

  store = X509_STORE_new ();
  cert = g_tls_certificate_openssl_get_cert (certificate);

  if (!X509_STORE_CTX_init(&csc, store, cert, NULL))
    goto end;

  trusted = sk_X509_new_null ();
  sk_X509_push (trusted, cert);

  X509_STORE_CTX_trusted_stack (&csc, trusted);
  X509_STORE_CTX_set_flags (&csc, X509_V_FLAG_CHECK_SS_SIGNATURE);

  ret = X509_verify_cert (&csc) > 0;

end:
  X509_STORE_CTX_cleanup (&csc);
  X509_STORE_free (store);

  return ret;
}

static gint
build_certificate_chain (GTlsDatabaseOpenssl     *openssl,
                         GTlsCertificateOpenssl  *chain,
                         const gchar             *purpose,
                         GSocketConnectable      *identity,
                         GTlsInteraction         *interaction,
                         GTlsDatabaseVerifyFlags  flags,
                         GCancellable            *cancellable,
                         GTlsCertificateOpenssl  **anchor,
                         GError                 **error)
{

  GTlsCertificateOpenssl *certificate;
  GTlsCertificateOpenssl *previous;
  GTlsCertificate *issuer;
  gboolean certificate_is_from_db;

  g_assert (anchor);
  g_assert (chain);
  g_assert (purpose);
  g_assert (error);
  g_assert (!*error);

  /*
   * Remember that the first certificate never changes in the chain.
   * When we find a self-signed, pinned or anchored certificate, all
   * issuers are truncated from the chain.
   */

  *anchor = NULL;
  previous = NULL;
  certificate = chain;
  certificate_is_from_db = FALSE;

  /* First check for pinned certificate */
  if (g_tls_database_openssl_lookup_assertion (openssl, certificate,
                                               G_TLS_DATABASE_OPENSSL_PINNED_CERTIFICATE,
                                               purpose, identity, cancellable, error))
    {
      g_tls_certificate_openssl_set_issuer (certificate, NULL);
      return STATUS_PINNED;
    }
  else if (*error)
    {
      return STATUS_FAILURE;
    }

  for (;;)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return STATUS_FAILURE;

      /* Look up whether this certificate is an anchor */
      if (g_tls_database_openssl_lookup_assertion (openssl, certificate,
                                                   G_TLS_DATABASE_OPENSSL_ANCHORED_CERTIFICATE,
                                                   purpose, identity, cancellable, error))
        {
          g_tls_certificate_openssl_set_issuer (certificate, NULL);
          *anchor = certificate;
          return STATUS_ANCHORED;
        }
      else if (*error)
        {
          return STATUS_FAILURE;
        }

      /* Is it self-signed? */
      if (is_self_signed (certificate))
        {
          /*
           * Since at this point we would fail with 'self-signed', can we replace
           * this certificate with one from the database and do better?
           */
          if (previous && !certificate_is_from_db)
            {
              issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (openssl),
                                                                 G_TLS_CERTIFICATE (previous),
                                                                 interaction,
                                                                 G_TLS_DATABASE_LOOKUP_NONE,
                                                                 cancellable, error);
              if (*error)
                {
                  return STATUS_FAILURE;
                }
              else if (issuer)
                {
                  /* Replaced with certificate in the db, restart step again with this certificate */
                  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
                  g_tls_certificate_openssl_set_issuer (previous, G_TLS_CERTIFICATE_OPENSSL (issuer));
                  certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
                  certificate_is_from_db = TRUE;
                  g_object_unref (issuer);
                  continue;
                }
            }

          g_tls_certificate_openssl_set_issuer (certificate, NULL);
          return STATUS_SELFSIGNED;
        }

      previous = certificate;

      /* Bring over the next certificate in the chain */
      issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (certificate));
      if (issuer)
        {
          g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
          certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
          certificate_is_from_db = FALSE;
        }

      /* Search for the next certificate in chain */
      else
        {
          issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (openssl),
                                                             G_TLS_CERTIFICATE (certificate),
                                                             interaction,
                                                             G_TLS_DATABASE_LOOKUP_NONE,
                                                             cancellable, error);
          if (*error)
            return STATUS_FAILURE;
          else if (!issuer)
            return STATUS_INCOMPLETE;

          /* Found a certificate in chain, use for next step */
          g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
          g_tls_certificate_openssl_set_issuer (certificate, G_TLS_CERTIFICATE_OPENSSL (issuer));
          certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
          certificate_is_from_db = TRUE;
          g_object_unref (issuer);
        }
    }

  g_assert_not_reached ();
}

static GTlsCertificateFlags
double_check_before_after_dates (GTlsCertificateOpenssl *chain)
{
  GTlsCertificateFlags gtls_flags = 0;
  X509 *cert;

  while (chain)
    {
      ASN1_TIME *not_before;
      ASN1_TIME *not_after;

      cert = g_tls_certificate_openssl_get_cert (chain);
      not_before = X509_get_notBefore (cert);
      not_after = X509_get_notAfter (cert);

      if (X509_cmp_current_time (not_before) > 0)
        gtls_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED;

      if (X509_cmp_current_time (not_after) < 0)
        gtls_flags |= G_TLS_CERTIFICATE_EXPIRED;

      chain = G_TLS_CERTIFICATE_OPENSSL (g_tls_certificate_get_issuer
                                         (G_TLS_CERTIFICATE (chain)));
    }

  return gtls_flags;
}

static STACK_OF(X509) *
convert_certificate_chain_to_openssl (GTlsCertificateOpenssl *chain)
{
  GTlsCertificate *cert;
  STACK_OF(X509) *openssl_chain;

  openssl_chain = sk_X509_new_null ();

  for (cert = G_TLS_CERTIFICATE (chain); cert; cert = g_tls_certificate_get_issuer (cert))
    sk_X509_push (openssl_chain, g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert)));

  return openssl_chain;
}

static GTlsCertificateFlags
g_tls_database_openssl_verify_chain (GTlsDatabase             *database,
                                     GTlsCertificate          *chain,
                                     const gchar              *purpose,
                                     GSocketConnectable       *identity,
                                     GTlsInteraction          *interaction,
                                     GTlsDatabaseVerifyFlags   flags,
                                     GCancellable             *cancellable,
                                     GError                  **error)
{
  GTlsDatabaseOpenssl *openssl;
  GTlsCertificateOpenssl *anchor;
  STACK_OF(X509) *certs, *anchors;
  X509_STORE *store;
  X509_STORE_CTX csc;
  X509 *x;
  gint status;
  GTlsCertificateFlags result = 0;
  GError *err = NULL;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);

  openssl = G_TLS_DATABASE_OPENSSL (database);
  anchor = NULL;

  status = build_certificate_chain (openssl, G_TLS_CERTIFICATE_OPENSSL (chain), purpose,
                                    identity, interaction, flags, cancellable, &anchor, &err);
  if (status == STATUS_FAILURE)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  /*
   * A pinned certificate is verified on its own, without any further
   * verification.
   */
  if (status == STATUS_PINNED)
      return 0;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  certs = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (chain));

  store = X509_STORE_new ();

  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (chain));
  if (!X509_STORE_CTX_init(&csc, store, x, certs))
    {
      X509_STORE_CTX_cleanup (&csc);
      X509_STORE_free (store);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  if (anchor)
    {
      g_assert (g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (anchor)) == NULL);
      anchors = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (anchor));
      X509_STORE_CTX_trusted_stack (&csc, anchors);
    }
  else
    anchors = NULL;

  if (X509_verify_cert (&csc) <= 0)
    result = g_tls_certificate_openssl_convert_error (X509_STORE_CTX_get_error (&csc));

  X509_STORE_CTX_cleanup (&csc);
  X509_STORE_free (store);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  /* We have to check these ourselves since openssl
   * does not give us flags and UNKNOWN_CA will take priority.
   */
  result |= double_check_before_after_dates (G_TLS_CERTIFICATE_OPENSSL (chain));

  if (identity)
    result |= g_tls_certificate_openssl_verify_identity (G_TLS_CERTIFICATE_OPENSSL (chain),
                                                         identity);

  return result;
}

static void
g_tls_database_openssl_class_init (GTlsDatabaseOpensslClass *klass)
{
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  database_class->verify_chain = g_tls_database_openssl_verify_chain;
}

static void
g_tls_database_openssl_init (GTlsDatabaseOpenssl *openssl)
{
}

gboolean
g_tls_database_openssl_lookup_assertion (GTlsDatabaseOpenssl          *openssl,
                                         GTlsCertificateOpenssl       *certificate,
                                         GTlsDatabaseOpensslAssertion  assertion,
                                         const gchar                  *purpose,
                                         GSocketConnectable           *identity,
                                         GCancellable                 *cancellable,
                                         GError                      **error)
{
  g_return_val_if_fail (G_IS_TLS_DATABASE_OPENSSL (openssl), FALSE);
  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (certificate), FALSE);
  g_return_val_if_fail (purpose, FALSE);
  g_return_val_if_fail (!identity || G_IS_SOCKET_CONNECTABLE (identity), FALSE);
  g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (!error || !*error, FALSE);
  g_return_val_if_fail (G_TLS_DATABASE_OPENSSL_GET_CLASS (openssl)->lookup_assertion, FALSE);
  return G_TLS_DATABASE_OPENSSL_GET_CLASS (openssl)->lookup_assertion (openssl,
                                                                       certificate,
                                                                       assertion,
                                                                       purpose,
                                                                       identity,
                                                                       cancellable,
                                                                       error);
}
