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
#include "libcowmail.h"
#include <gio/gio.h>
#include <nettle/sha2.h>



typedef struct {
  guchar *head;
  guchar *body;
  gsize   size;
} cowmail_item;



GHashTable *table;
GMutex table_lock;



static void
list_messages (GOutputStream *ostream)
{
  g_autoptr (GError) error = NULL;
  g_mutex_lock (&table_lock);
  gint c = 0;
  for (GList *item = g_hash_table_get_values(table); item; item = item->next) {
    g_output_stream_write (ostream, ((cowmail_item *) item->data)->head, COWMAIL_HEAD_SIZE, NULL, &error);
    if (error) {
      g_printerr("LIST: Breaking loop because of ERROR in round %d: %s\n", c, error->message);
      break;
    }
    c++;
  }
  g_mutex_unlock (&table_lock);
}



static void
get_message (GOutputStream *ostream,
             const guchar  *hash)
{
  g_autoptr (GError) error = NULL;

  g_mutex_lock (&table_lock);
  cowmail_item *item = g_hash_table_lookup (table, hash);
  if (!item) {
    g_printerr ("COWMAIL ERROR: Item not found.\n");
    return;
  }
  g_output_stream_write (ostream, item->body, item->size, NULL, &error);
  if (error)
    g_printerr ("GET ERROR: %s\n", error->message);
  g_hash_table_remove (table, hash);
  g_mutex_unlock (&table_lock);

  g_free (item->body);
  g_free (item->head);
  g_free (item);
}



static void
put_message (const guchar *data,
             gsize         size)
{
  const guchar *body = data + COWMAIL_HEAD_SIZE;

  cowmail_item *item = g_new (cowmail_item, 1);
  item->head = g_memdup (data, COWMAIL_HEAD_SIZE);
  item->size = size - COWMAIL_HEAD_SIZE;
  item->body = g_memdup (body, item->size);

  struct sha256_ctx sha;
  guchar *hash = g_malloc (COWMAIL_KEY_SIZE);
  sha256_init (&sha);
  sha256_update (&sha, item->size, body);
  sha256_digest (&sha, COWMAIL_KEY_SIZE, hash);

  g_mutex_lock (&table_lock);
  g_hash_table_insert (table, hash, item);
  g_mutex_unlock (&table_lock);
}



static void
process_request (GOutputStream *ostream,
                 const guchar  *data,
                 size_t         dsize)
{
  if (dsize == 1) {
    g_print ("LIST command. Byte: [%02x]\n", *data);
    list_messages (ostream);
    return;
  }
  if (dsize == COWMAIL_KEY_SIZE) {
    g_autofree gchar *hash = g_base64_encode (data, COWMAIL_KEY_SIZE);
    g_print ("GET command. Hash: [%s]\n", hash);
    get_message (ostream, data);
    return;
  }
  if (dsize > COWMAIL_HEAD_SIZE + COWMAIL_TAG_SIZE) {
    g_autofree gchar *head = g_base64_encode (data, COWMAIL_HEAD_SIZE);
    g_print ("PUT command. Message of size %" G_GSIZE_FORMAT ". Head: [%s]\n", dsize - COWMAIL_HEAD_SIZE, head);
    put_message (data, dsize);
    return;
  }
  g_printerr ("ERROR: Invalid cowmail command.\n");
  return;
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

  g_autoptr (GError) error = NULL;
  GInputStream *istream = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  GOutputStream *ostream = g_io_stream_get_output_stream (G_IO_STREAM (connection));

  guchar *request = g_malloc (65536);
  size_t size = g_input_stream_read (istream, request, 65536, NULL, &error);
  if (!error) {
    process_request (ostream, request, size);
  } else {
    g_printerr ("ERROR: %s\n", error->message);
  }
  return FALSE;
}



static guint
cowmail_key_hash (gconstpointer *key)
{
  return *((guint *) key);
}



static gboolean
cowmail_key_equal (gconstpointer *key1,
                   gconstpointer *key2)
{
  return !(memcmp (key1, key2, COWMAIL_KEY_SIZE));
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

  g_print ("cowmail server version %s started.\n", PACKAGE_VERSION);

  table = g_hash_table_new_full ((GHashFunc) cowmail_key_hash, (GEqualFunc) cowmail_key_equal, NULL, NULL);

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
