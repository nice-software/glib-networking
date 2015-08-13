/*
 * gtlsbackend-openssl.c
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
#include "glib.h"

#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>

#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include "gtlsserverconnection-openssl.h"
#include "gtlsclientconnection-openssl.h"
#include "gtlsfiledatabase-openssl.h"

typedef struct _GTlsBackendOpensslPrivate
{
  GMutex mutex;
  GTlsDatabase *default_database;
} GTlsBackendOpensslPrivate;

static void g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendOpenssl, g_tls_backend_openssl, G_TYPE_OBJECT, 0,
                                G_ADD_PRIVATE_DYNAMIC (GTlsBackendOpenssl)
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_openssl_interface_init))

static gpointer
gtls_openssl_init (gpointer data)
{
  SSL_library_init ();
  SSL_load_error_strings ();

  /* Leak the module to keep it from being unloaded. */
  g_type_plugin_use (g_type_get_plugin (G_TYPE_TLS_BACKEND_OPENSSL));
  return NULL;
}

static GOnce openssl_inited = G_ONCE_INIT;

static void
g_tls_backend_openssl_init (GTlsBackendOpenssl *backend)
{
  GTlsBackendOpensslPrivate *priv;

  priv = g_tls_backend_openssl_get_instance_private (backend);

  /* Once we call gtls_openssl_init(), we can't allow the module to be
   * unloaded (since if openssl gets unloaded but gcrypt doesn't, then
   * gcrypt will have dangling pointers to openssl's mutex functions).
   * So we initialize it from here rather than at class init time so
   * that it doesn't happen unless the app is actually using TLS (as
   * opposed to just calling g_io_modules_scan_all_in_directory()).
   */
  g_once (&openssl_inited, gtls_openssl_init, NULL);

  g_mutex_init (&priv->mutex);
}

static void
g_tls_backend_openssl_finalize (GObject *object)
{
  GTlsBackendOpenssl *backend = G_TLS_BACKEND_OPENSSL (object);
  GTlsBackendOpensslPrivate *priv;

  priv = g_tls_backend_openssl_get_instance_private (backend);

  g_clear_object (&priv->default_database);
  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (g_tls_backend_openssl_parent_class)->finalize (object);
}

static GTlsDatabase *
g_tls_backend_openssl_real_create_database (GTlsBackendOpenssl  *self,
                                           GError            **error)
{
  const gchar *anchor_file = NULL;
#ifdef GTLS_SYSTEM_CA_FILE
  anchor_file = GTLS_SYSTEM_CA_FILE;
#endif
  return g_tls_file_database_new (anchor_file, error);
}

static void
g_tls_backend_openssl_class_init (GTlsBackendOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = g_tls_backend_openssl_finalize;

  klass->create_database = g_tls_backend_openssl_real_create_database;
}

static void
g_tls_backend_openssl_class_finalize (GTlsBackendOpensslClass *backend_class)
{
}

static GTlsDatabase*
g_tls_backend_openssl_get_default_database (GTlsBackend *backend)
{
  GTlsBackendOpenssl *openssl_backend = G_TLS_BACKEND_OPENSSL (backend);
  GTlsBackendOpensslPrivate *priv;
  GTlsDatabase *result;
  GError *error = NULL;

  priv = g_tls_backend_openssl_get_instance_private (openssl_backend);

  g_mutex_lock (&priv->mutex);

  if (priv->default_database)
    {
      result = g_object_ref (priv->default_database);
    }
  else
    {
      g_assert (G_TLS_BACKEND_OPENSSL_GET_CLASS (openssl_backend)->create_database);
      result = G_TLS_BACKEND_OPENSSL_GET_CLASS (openssl_backend)->create_database (openssl_backend, &error);
      if (error)
        {
          g_warning ("Couldn't load TLS file database: %s",
                     error->message);
          g_clear_error (&error);
        }
      else
        {
          g_assert (result);
          priv->default_database = g_object_ref (result);
        }
    }

  g_mutex_unlock (&priv->mutex);

  return result;
}

static void
g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type = g_tls_certificate_openssl_get_type;
  iface->get_client_connection_type = g_tls_client_connection_openssl_get_type;
  iface->get_server_connection_type = g_tls_server_connection_openssl_get_type;
  iface->get_file_database_type = g_tls_file_database_openssl_get_type;
  iface->get_default_database = g_tls_backend_openssl_get_default_database;
}

void
g_tls_backend_openssl_register (GIOModule *module)
{
  g_tls_backend_openssl_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_openssl_get_type(),
                                  "openssl",
                                  0);
}
