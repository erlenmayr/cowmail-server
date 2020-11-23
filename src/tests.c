/* tests.c
 *
 * Copyright 2020 Stephan Verbücheln
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libcowmail.h"
#include <gio/gio.h>
#include <nettle/sha2.h>



void
cowmail_put (const gchar *hostname,
             guint16      port,
             guchar      *item,
             gsize        size)
{
  g_autoptr (GError) error = NULL;

  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_socket_client_set_protocol (client, G_SOCKET_PROTOCOL_SCTP);
  g_autoptr (GSocketConnection) connection;
  if ((connection = g_socket_client_connect_to_host (client, hostname, port, NULL, &error))) {
    GOutputStream *ostream = g_io_stream_get_output_stream (G_IO_STREAM (connection));
    g_output_stream_write (ostream, item, size, NULL, &error);
    g_print ("PUT: Item of size %" G_GSIZE_FORMAT ".\n", size);
  } else {
    g_printerr ("PUT ERROR: %s\n", error->message);
  }
}



guchar *
cowmail_list (const gchar *hostname,
              guint16      port)
{
  g_autoptr (GError) error = NULL;
  g_autofree guchar *cryptotext = g_malloc (1);

  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_socket_client_set_protocol (client, G_SOCKET_PROTOCOL_SCTP);
  g_autoptr (GSocketConnection) connection;
  if ((connection = g_socket_client_connect_to_host (client, hostname, port, NULL, &error))) {
    GOutputStream *ostream = g_io_stream_get_output_stream (G_IO_STREAM (connection));
    g_output_stream_write (ostream, cryptotext, 1, NULL, &error);
    g_print ("LIST: Sending command byte.\n");
    GInputStream *istream = g_io_stream_get_input_stream (G_IO_STREAM (connection));
    guchar *buf = g_malloc (COWMAIL_HEAD_SIZE + 1);
    gsize len;
    while ((len = g_input_stream_read (istream, buf, COWMAIL_HEAD_SIZE, NULL, &error)) == COWMAIL_HEAD_SIZE) {
      g_print ("LIST: Received header of valid size.\n");
      buf[COWMAIL_HEAD_SIZE] = '\0';
      return buf;
    }
  } else {
    g_printerr ("LIST ERROR: %s\n", error->message);
  }
  return NULL;
}



guchar *
cowmail_get (const gchar *hostname,
             guint16      port,
             guchar      *hash)
{
  g_autoptr (GError) error = NULL;

  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_socket_client_set_protocol (client, G_SOCKET_PROTOCOL_SCTP);
  g_autoptr (GSocketConnection) connection;
  if ((connection = g_socket_client_connect_to_host (client, hostname, port, NULL, &error))) {
    GOutputStream *ostream = g_io_stream_get_output_stream (G_IO_STREAM (connection));
    g_output_stream_write (ostream, hash, COWMAIL_KEY_SIZE, NULL, &error);
    g_print ("GET: Sending message hash.\n");
    GInputStream *istream = g_io_stream_get_input_stream (G_IO_STREAM (connection));
    guchar *buf = g_malloc (65536);
    gsize len = g_input_stream_read (istream, buf, 65536, NULL, &error);
    if (len > 0) {
      g_print ("GET: Received message of size %" G_GSIZE_FORMAT ".\n", len);
      return buf;
    }  else {
      g_printerr ("GET ERROR: %s\n", error->message);
    }
  } else {
    g_printerr ("GET ERROR: %s\n", error->message);
  }
  return NULL;
}



guchar *
hash_item (guchar *item,
           gsize   size)
{
  guchar *hash = g_malloc (COWMAIL_KEY_SIZE);
  struct sha256_ctx sha;
  sha256_init (&sha);
  sha256_update (&sha, size - COWMAIL_HEAD_SIZE, item + COWMAIL_HEAD_SIZE);
  sha256_digest (&sha, COWMAIL_KEY_SIZE, hash);
  return hash;
}



int
main ()
{
  /*                               HEAD (80 bytes)                                                  /   BODY                       */
  gchar *item = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZqwertyuiopasdfghjklzxcvbmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";
  gsize len = strlen (item) + 1;
  guchar *hash = hash_item ((guchar *) item, len);

  cowmail_put ("localhost", 1337, (guchar *) item, len);

  sleep (1);

  guchar *hd = cowmail_list ("localhost", 1337);
  gchar *head = g_malloc0 (COWMAIL_HEAD_SIZE + 1);
  memcpy (head, hd, COWMAIL_HEAD_SIZE);

  sleep (1);

  gchar *msg = (gchar *) cowmail_get ("localhost", 1337, hash);

  g_print ("Received message: [%s%s]\n", head, msg);

  return 0;
}
