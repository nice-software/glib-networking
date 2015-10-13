/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 */

#include "config.h"
#include "gtlsinputstream-base.h"

static void g_tls_input_stream_base_pollable_iface_init (GPollableInputStreamInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsInputStreamBase, g_tls_input_stream_base, G_TYPE_INPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM, g_tls_input_stream_base_pollable_iface_init)
			 )

struct _GTlsInputStreamBasePrivate
{
  GTlsConnectionBase *conn;
};

static void
g_tls_input_stream_base_dispose (GObject *object)
{
  GTlsInputStreamBase *stream = G_TLS_INPUT_STREAM_BASE (object);

  if (stream->priv->conn)
    {
      g_object_remove_weak_pointer (G_OBJECT (stream->priv->conn),
				    (gpointer *)&stream->priv->conn);
      stream->priv->conn = NULL;
    }

  G_OBJECT_CLASS (g_tls_input_stream_base_parent_class)->dispose (object);
}

static gssize
g_tls_input_stream_base_read (GInputStream  *stream,
			      void          *buffer,
			      gsize          count,
			      GCancellable  *cancellable,
			      GError       **error)
{
  GTlsInputStreamBase *tls_stream = G_TLS_INPUT_STREAM_BASE (stream);

  g_return_val_if_fail (tls_stream->priv->conn != NULL, -1);

  return g_tls_connection_base_read (tls_stream->priv->conn,
				     buffer, count, TRUE,
				     cancellable, error);
}

static gboolean
g_tls_input_stream_base_pollable_is_readable (GPollableInputStream *pollable)
{
  GTlsInputStreamBase *tls_stream = G_TLS_INPUT_STREAM_BASE (pollable);

  g_return_val_if_fail (tls_stream->priv->conn != NULL, FALSE);

  return g_tls_connection_base_check (tls_stream->priv->conn, G_IO_IN);
}

static GSource *
g_tls_input_stream_base_pollable_create_source (GPollableInputStream *pollable,
						GCancellable         *cancellable)
{
  GTlsInputStreamBase *tls_stream = G_TLS_INPUT_STREAM_BASE (pollable);

  g_return_val_if_fail (tls_stream->priv->conn != NULL, NULL);

  return g_tls_connection_base_create_source (tls_stream->priv->conn,
					      G_IO_IN,
					      cancellable);
}

static gssize
g_tls_input_stream_base_pollable_read_nonblocking (GPollableInputStream  *pollable,
						   void                  *buffer,
						   gsize                  size,
						   GError               **error)
{
  GTlsInputStreamBase *tls_stream = G_TLS_INPUT_STREAM_BASE (pollable);

  return g_tls_connection_base_read (tls_stream->priv->conn,
				     buffer, size, FALSE,
				     NULL, error);
}

static void
g_tls_input_stream_base_class_init (GTlsInputStreamBaseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsInputStreamBasePrivate));

  gobject_class->dispose = g_tls_input_stream_base_dispose;

  input_stream_class->read_fn = g_tls_input_stream_base_read;
}

static void
g_tls_input_stream_base_pollable_iface_init (GPollableInputStreamInterface *iface)
{
  iface->is_readable = g_tls_input_stream_base_pollable_is_readable;
  iface->create_source = g_tls_input_stream_base_pollable_create_source;
  iface->read_nonblocking = g_tls_input_stream_base_pollable_read_nonblocking;
}

static void
g_tls_input_stream_base_init (GTlsInputStreamBase *stream)
{
  stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream, G_TYPE_TLS_INPUT_STREAM_BASE, GTlsInputStreamBasePrivate);
}

GInputStream *
g_tls_input_stream_base_new (GTlsConnectionBase *conn)
{
  GTlsInputStreamBase *tls_stream;

  tls_stream = g_object_new (G_TYPE_TLS_INPUT_STREAM_BASE, NULL);
  tls_stream->priv->conn = conn;
  g_object_add_weak_pointer (G_OBJECT (conn),
			     (gpointer *)&tls_stream->priv->conn);

  return G_INPUT_STREAM (tls_stream);
}
