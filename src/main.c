/* main.c
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

#include "cowmail_server-config.h"
#include <gio/gio.h>



typedef struct {
  gchar *head;
  gchar *body;
} message;



GHashTable *table;
GMutex table_lock;



static void
store_message (gchar *head,
               gchar *body)
{
  gchar *key = g_compute_checksum_for_string (G_CHECKSUM_SHA256, body, -1);
  message *msg = g_new (message, 1);
  msg->head = strdup (head);
  msg->body = strdup (body);

  g_print ("Storing: [%s] [%s] -> [%s]\n", head, body, key);
  g_mutex_lock (&table_lock);
  g_hash_table_insert (table, key, msg);
  g_mutex_unlock (&table_lock);
}



static gchar *
get_message (gchar *hash)
{
  g_mutex_lock (&table_lock);
  message *msg = g_hash_table_lookup (table, hash);
  g_hash_table_remove (table, hash);
  g_mutex_unlock (&table_lock);
  gchar *text = g_strconcat (msg->body, "\n", NULL);
  g_free (msg->head);
  g_free (msg->body);
  g_free (msg);
  return text;
}



static gchar *
list_messages ()
{
  g_mutex_lock (&table_lock);
  GHashTableIter iter;
  g_hash_table_iter_init (&iter, table);
  gchar *k;
  message *v;
  GString *buf = g_string_new (NULL);
  while (g_hash_table_iter_next (&iter, (void **) &k, (void **) &v)) {
    buf = g_string_append (buf, v->head);
    buf = g_string_append (buf, "\n");
  }
  g_mutex_unlock (&table_lock);
  // TODO: free GString
  return buf->str;
}



static gchar *
process_message (gchar *data)
{
  gchar *ret = NULL;
  gchar **msg = g_strsplit_set (data, " \n", 4);
  if (!g_strcmp0 (msg[0], "LIST")) {
    g_print ("LIST command: [%s]\n", msg[0]);
    ret = list_messages ();
  } else if (!g_strcmp0 (msg[0], "GET") && msg[1]) {
    g_print ("GET command: [%s] [%s]\n", msg[0], msg[1]);
    ret = get_message (msg[1]);
  } else if (!g_strcmp0 (msg[0], "PUT") && msg[1] && msg[2]) {
    g_print ("PUT command: [%s] [%s] [%s]\n", msg[0], msg[1], msg[2]);
    store_message (msg[1], msg[2]);
  } else {
    g_printerr ("Invalid command: [%s]\n", msg[0]);
  }
  g_strfreev (msg);
  return ret;
}



static void
send_messages (GDataOutputStream *ostream,
               const gchar       *msg)
{
  g_print ("Sending: [%s]\n", msg);
  g_data_output_stream_put_string (ostream, msg, NULL, NULL);

}



static gboolean
incoming_cb (GSocketService    *service,
             GSocketConnection *connection,
             GObject           *source_object,
             gpointer           user_data)
{
  g_assert_null (source_object);
  g_assert_null (user_data);
  G_IS_SOCKET_SERVICE (service);

  GError *error = NULL;
  GDataInputStream *dstream = g_data_input_stream_new (g_io_stream_get_input_stream (G_IO_STREAM (connection)));
  GDataOutputStream *ostream = g_data_output_stream_new (g_io_stream_get_output_stream (G_IO_STREAM (connection)));
  char *buf = NULL;

  if ((buf = g_data_input_stream_read_line_utf8 (dstream, NULL, NULL, &error))) {
    gchar *msg = process_message (buf);
    if (msg)
      send_messages (ostream, msg);
    g_free (buf);
  }

  if (!g_io_stream_close (G_IO_STREAM (connection), NULL, &error)) {
    g_error ("Connection closing problem: %s\n", error->message);
  }

  g_object_unref (ostream);
  g_object_unref (dstream);
  return FALSE;
}



gint
main (gint   argc,
      gchar *argv[])
{
  g_autoptr (GOptionContext) context = NULL;
  g_autoptr (GError) error = NULL;
  gboolean op_version = FALSE;
  gint op_port = 1337;

  GOptionEntry main_entries[] = {
    { "version", '\0', 0, G_OPTION_ARG_NONE, &op_version, "Show program version",               NULL },
    { "port",    'p',  0, G_OPTION_ARG_INT,  &op_port,    "Define port number (default: 1337)", NULL },
    { NULL,      '\0', 0, 0,                 NULL,        NULL,                                 NULL }
  };

  context = g_option_context_new ("- cowmail server daemon");
  g_option_context_add_main_entries (context, main_entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("%s\n", error->message);
    return EXIT_FAILURE;
  }

  if (op_version) {
    g_printerr ("cowmail server version %s.\n", PACKAGE_VERSION);
    return EXIT_SUCCESS;
  }

  table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  GSocketService *service = g_threaded_socket_service_new (-1);
  GSocketListener *listener = G_SOCKET_LISTENER (service);
  GSocketAddress *address = G_SOCKET_ADDRESS (g_inet_socket_address_new (g_inet_address_new_any (G_SOCKET_FAMILY_IPV6), op_port));
  if (!g_socket_listener_add_address (listener, address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_SCTP, NULL, NULL, &error)) {
    g_printerr ("%s\n", error->message);
    return EXIT_FAILURE;
  }
  g_signal_connect (service, "incoming", G_CALLBACK (incoming_cb), NULL);

  GMainLoop *loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  return EXIT_SUCCESS;
}
