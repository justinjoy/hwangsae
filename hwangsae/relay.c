/**
 *  Copyright 2019 SK Telecom Co., Ltd.
 *    Author: Jeongseok Kim <jeongseok.kim@sk.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "relay.h"
#include "relay-map.h"
#include "relay-internal.h"

#include <gio/gio.h>

struct _HwangsaeRelay
{
  GObject parent;

  GThread *thread;
  GMutex lock;
  GCond cond;
  GMainContext *context;
  GMainLoop *loop;

  GSettings *settings;

  guint sink_port;
  guint source_port;

  SRTSOCKET sink_listen_sock;
  SRTSOCKET source_listen_sock;

  gint sink_poll_id;

  HwangsaeRelayMap *map;
};

static guint hwangsae_relay_init_refcnt = 0;

/* *INDENT-OFF* */
G_DEFINE_TYPE (HwangsaeRelay, hwangsae_relay, G_TYPE_OBJECT);
/* *INDENT-ON* */

enum
{
  PROP_SINK_PORT = 1,
  PROP_SOURCE_PORT,
  PROP_LAST
};

struct srt_constant_params
{
  const gchar *name;
  gint param;
  gint val;
};

static struct srt_constant_params srt_params[] = {
  {"SRTO_SNDSYN", SRTO_SNDSYN, 0},      /* 0: non-blocking */
  {"SRTO_RCVSYN", SRTO_RCVSYN, 0},      /* 0: non-blocking */
  {"SRTO_LINGER", SRTO_LINGER, 0},
  {"SRTO_TSBPMODE", SRTO_TSBPDMODE, 1}, /* Timestamp-based Packet Delivery mode must be enabled */
  {"SRTO_RENDEZVOUS", SRTO_RENDEZVOUS, 0},      /* 0: not for rendezvous */
  {NULL, -1, -1},
};

static void
hwangsae_relay_dispose (GObject * object)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);

  if (self->loop) {
    g_main_loop_quit (self->loop);

    if (self->thread != g_thread_self ())
      g_thread_join (self->thread);
    else
      g_clear_pointer (&self->thread, g_thread_unref);

    g_clear_pointer (&self->loop, g_main_loop_unref);
    g_clear_pointer (&self->context, g_main_context_unref);
  }

  g_clear_object (&self->settings);

  g_clear_pointer (&self->map, hwangsae_relay_map_unref);

  G_OBJECT_CLASS (hwangsae_relay_parent_class)->dispose (object);
}

static void
hwangsae_relay_finalize (GObject * object)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);

  g_mutex_clear (&self->lock);
  g_cond_clear (&self->cond);

  if (g_atomic_int_dec_and_test (&hwangsae_relay_init_refcnt)) {
    g_debug ("Cleaning up SRT");
    srt_cleanup ();
  }

  G_OBJECT_CLASS (hwangsae_relay_parent_class)->finalize (object);
}

static void
hwangsae_relay_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);

  switch (prop_id) {
    case PROP_SINK_PORT:
      self->sink_port = g_value_get_uint (value);
      break;
    case PROP_SOURCE_PORT:
      self->source_port = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

static void
hwangsae_relay_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);
  switch (prop_id) {
    case PROP_SINK_PORT:
      g_value_set_uint (value, self->sink_port);
      break;
    case PROP_SOURCE_PORT:
      g_value_set_uint (value, self->source_port);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

static gboolean
_main_loop_running_cb (gpointer data)
{
  HwangsaeRelay *self = data;

  g_debug ("Main loop running now");

  g_mutex_lock (&self->lock);
  g_cond_signal (&self->cond);
  g_mutex_unlock (&self->lock);

  return G_SOURCE_REMOVE;
}

static void
_apply_socket_options (SRTSOCKET sock)
{
  struct srt_constant_params *params = srt_params;

  for (; params->name != NULL; params++) {
    if (srt_setsockflag (sock, params->param, &params->val, sizeof (gint))) {
      g_error ("%s", srt_getlasterror_str ());
    }
  }
}

static SRTSOCKET
_srt_open_listen_sock (guint port, gint limit)
{
  g_autoptr (GSocketAddress) sockaddr = NULL;
  g_autoptr (GError) error = NULL;

  SRTSOCKET listen_sock;
  gsize sockaddr_len;
  gpointer sa;

  g_debug ("opening srt listener (port: %" G_GUINT32_FORMAT ")", port);

  /* FIXME: use user-defined bind address */
  sockaddr = g_inet_socket_address_new_from_string ("0.0.0.0", port);
  sockaddr_len = g_socket_address_get_native_size (sockaddr);

  sa = g_alloca (sockaddr_len);

  if (!g_socket_address_to_native (sockaddr, sa, sockaddr_len, &error)) {
    goto failed;
  }

  listen_sock = srt_socket (AF_INET, SOCK_DGRAM, 0);
  _apply_socket_options (listen_sock);

  if (srt_bind (listen_sock, sa, sockaddr_len) == SRT_ERROR) {
    goto srt_failed;
  }

  if (srt_listen (listen_sock, limit) == SRT_ERROR) {
    goto srt_failed;
  }

  return listen_sock;

srt_failed:
  g_error ("%s", srt_getlasterror_str ());

  if (listen_sock != SRT_INVALID_SOCK) {
    srt_close (listen_sock);
  }

failed:

  if (error != NULL) {
    g_error ("%s", error->message);
  }

  return SRT_INVALID_SOCK;
}

#if  0
static HwangsaeHostInfo *
_srt_listen_cb_internal (HwangsaeRelay * self, SRTSOCKET sock, gint hs_version,
    const struct sockaddr *peeraddr, const gchar * stream_id,
    HwangsaeSRTMode mode, HwangsaeDirection direction)
{
  g_autoptr (GSocketAddress) addr = NULL;
  g_autofree gchar *addr_str = NULL;
  g_autofree gchar *valid_stream_id = NULL;
  g_autoptr (GMutexLocker) locker = NULL;
  GInetAddress *inet_addr;
  gint sockflag = direction == HWANGSAE_DIRECTION_SOURCE ? 1 : 0;

  g_autoptr (HwangsaeHostInfo) info = NULL;

  addr =
      g_socket_address_new_from_native ((gpointer) peeraddr,
      sizeof (struct sockaddr));
  inet_addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
  addr_str = g_inet_address_to_string (inet_addr);

  valid_stream_id =
      stream_id != NULL ? g_strdup (stream_id) : (direction ==
      HWANGSAE_DIRECTION_SINK) ? g_strdup ("default") : g_uuid_string_random ();

  g_debug ("accepting a %s connection from [%s:%" G_GUINT16_FORMAT
      "], stream-id: %s",
      (direction == HWANGSAE_DIRECTION_SOURCE) ? "source" : "sink", addr_str,
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)),
      valid_stream_id);

  info =
      srt_info_new (addr, valid_stream_id, sock, mode, direction, hs_version);

  _apply_socket_options (sock);

  if (srt_setsockflag (sock, SRTO_SENDER, &sockflag, sizeof (gint))) {
    goto srt_failed;
  }

  /* *INDENT-ON* */

  locker = g_mutex_locker_new (&self->lock);
  if (g_hash_table_lookup (self->sink_map, valid_stream_id) != NULL) {
    g_debug ("refuse connection due to duplication");
    goto failed;                /* refuse connection */
  }

  if (direction == HWANGSAE_DIRECTION_SOURCE) {
    g_hash_table_insert (self->source_map, GINT_TO_POINTER (sock),
        srt_info_ref (info));
  } else {
    g_hash_table_insert (self->sink_map,
        g_steal_pointer (&valid_stream_id), srt_info_ref (info));
  }

  return g_steal_pointer (&info);       /* connection accepted */

srt_failed:

  g_error ("%s", srt_getlasterror_str ());

failed:
  srt_close (sock);

  return NULL;                  /* error */

}
#endif

static gint
_sink_listen_cb (HwangsaeRelay * self, SRTSOCKET sock, gint hs_version,
    const struct sockaddr *peeraddr, const gchar * stream_id)
{
  g_autoptr (GSocketAddress) addr = NULL;
  g_autofree gchar *addr_str = NULL;
  g_autofree gchar *valid_stream_id = NULL;
  GInetAddress *inet_addr;
  HwangsaeHostInfo *info = NULL;

  addr =
      g_socket_address_new_from_native ((gpointer) peeraddr,
      sizeof (struct sockaddr));
  inet_addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
  addr_str = g_inet_address_to_string (inet_addr);

  valid_stream_id =
      stream_id != NULL
      && *stream_id != '\0' ? g_strdup (stream_id) : g_strdup ("default");

  info =
      hwangsae_relay_map_add_sink (self->map, addr, valid_stream_id, sock,
      hs_version, HWANGSAE_SRT_MODE_CALLER);

  if (info == NULL) {
    g_debug ("fail to add a sink connection from %s", addr_str);
    goto reject;
  }

  g_debug ("accepting a sink connection from [%s:%" G_GUINT16_FORMAT
      "], stream-id: %s (sock: 0x%x)", addr_str,
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)),
      valid_stream_id, sock);

  if (srt_epoll_add_usock (self->sink_poll_id, sock, &(gint) {
          SRT_EPOLL_ERR | SRT_EPOLL_IN}
      )) {
    g_error ("%s", srt_getlasterror_str ());
    goto reject;
  }

  /* TODO: need to set passphrase from external key management system */
  srt_setsockflag (sock, SRTO_PASSPHRASE, "123456789!", 10);

  return 0;

reject:

  if (info) {
    hwangsae_relay_map_remove (self->map, info->stream_id);
  }

  srt_close (sock);

  return -1;
}

static gint
_source_listen_cb (HwangsaeRelay * self, SRTSOCKET sock, gint hs_version,
    const struct sockaddr *peeraddr, const gchar * stream_id)
{
#if 0
  HwangsaeHotInfo *info = NULL;
  g_autoptr (GMutexLocker) locker = NULL;
  gint source_poll_id;
  gchar *sink_stream_id;

  locker = g_mutex_locker_new (&self->lock);
  if (g_hash_table_size (self->sink_map) < 1) {
    /* No sink stream */
    g_debug ("no sink stream is ready");
    return -1;
  }
  g_mutex_locker_free (locker);

  info = _srt_listen_cb_internal (self, sock, hs_version, peeraddr, stream_id,
      HWANGSAE_SRT_MODE_CALLER, HWANGSAE_DIRECTION_SOURCE);

  if (info == NULL) {
    srt_close (sock);
    goto reject;
  }

  locker = g_mutex_locker_new (&self->lock);
  sink_stream_id = g_hash_table_lookup (self->reverse_map, stream_id);
  if (stream_id == NULL) {
    g_debug ("no mapped sink found");
    goto reject;
  }

  source_poll_id =
      GPOINTER_TO_INT (g_hash_table_lookup (self->sink_map, sink_stream_id));

  if (srt_epoll_add_usock (source_poll_id, sock, &(gint) {
          SRT_EPOLL_ERR | SRT_EPOLL_OUT}
      )) {
    g_error ("%s", srt_getlasterror_str ());
    goto reject;
  }

  return 0;

reject:
#endif
  return -1;
}

static void
_relay_to (HwangsaeRelay * self, gchar * stream_id, guint8 * payload, gint len)
{
  g_debug ("drop payload (len: %d)", len);
#if 0
  g_autoptr (GMutexLocker) locker = NULL;
  gint source_poll_id;
  SRT_EPOLL_EVENT *source_events;
  gint i, event_len;

  locker = g_mutex_locker_new (&self->lock);
  source_poll_id =
      GPOINTER_TO_INT (g_hash_table_lookup (self->relay_map, stream_id));
  g_mutex_locker_free (locker);

  if (source_poll_id == 0) {
    g_debug ("not found associated source poll id for %s", stream_id);
    return;
  }

  locker = g_mutex_locker_new (&self->lock);
  event_len = g_hash_table_size (self->source_map);
  g_mutex_locker_free (locker);
  source_events = g_new0 (SRT_EPOLL_EVENT, event_len);

  if (srt_epoll_uwait (source_poll_id, source_events, event_len, 0) < 0) {
    g_error ("%s", srt_getlasterror_str ());
    goto out;
  }

  for (i = 0; i < event_len; i++) {
    SRTInfo *info = NULL;
    gint sent;

    locker = g_mutex_locker_new (&self->lock);
    info =
        g_hash_table_lookup (self->source_map,
        GINT_TO_POINTER (source_events[i].fd));
    g_mutex_locker_free (locker);

    switch (srt_getsockstate (source_events[i].fd)) {
      case SRTS_BROKEN:
      case SRTS_NONEXIST:
      case SRTS_CLOSED:
        g_warning ("Invalid SRT source socket (%s)", info->stream_id);

        srt_epoll_remove_usock (source_poll_id, source_events[i].fd);
        locker = g_mutex_locker_new (&self->lock);
        g_hash_table_remove (self->reverse_map, info->stream_id);
        g_hash_table_remove (self->source_map,
            GINT_TO_POINTER (source_events[i].fd));
        g_mutex_locker_free (locker);

        goto out;

      case SRTS_CONNECTED:
        /* good to go */
        break;
      default:
        /* not-ready */
        goto out;
    }

    /* FIXME: need to find proper ttl  */
    sent = srt_sendmsg (source_events[i].fd, (char *) payload, len, 125, 0);
    g_debug ("sent buffer to %s (%d/%d)", info->stream_id, sent, len);

  }

out:

  if (source_events != NULL) {
    g_free (source_events);
  }
#endif
}

static void
_invalidate_sink_func (gpointer data, gpointer user_data)
{
  HwangsaeRelay *self = user_data;
  g_autofree gchar *sink_stream_id = g_strdup (data);
  HwangsaeHostInfo *info =
      hwangsae_relay_map_get_info (self->map, sink_stream_id);

  g_debug ("invalidating (%s)", sink_stream_id);
  switch (srt_getsockstate (info->sock)) {
    case SRTS_BROKEN:
    case SRTS_NONEXIST:
    case SRTS_CLOSED:
      g_debug ("invalidate sink (stream-id: %s)", sink_stream_id);
      srt_epoll_remove_usock (self->sink_poll_id, info->sock);
      hwangsae_relay_map_remove (self->map, sink_stream_id);
      break;
    default:
      break;
  }
}

static gboolean
_relay_running_cb (gpointer data)
{
  HwangsaeRelay *self = data;
  SRT_EPOLL_EVENT *sink_events;
  gint i, event_len;

  event_len = hwangsae_relay_map_sink_count (self->map);
  sink_events = g_new0 (SRT_EPOLL_EVENT, event_len);

  if (event_len == 0) {
    return G_SOURCE_CONTINUE;
  }

  if (srt_epoll_uwait (self->sink_poll_id, sink_events, event_len, 100) <= 0) {
    /* SRT has two authorization steps; by listener callback, then by passphrase
     *
     * User only can decide whether stream-id is validated.
     * If passphrase is not matches, SRT will reject connection request.
     * However, the problem is that we don't know whether the socket which is accepted by
     * listener callback is passed SRT's authentication step or not.
     * The invalidated socket will be detected by epoll_wait as error.
     */

    g_autoptr (GList) sinks = hwangsae_relay_map_get_sink_ids (self->map);
    g_list_foreach (sinks, _invalidate_sink_func, self);
    goto out;
  }

  for (i = 0; i < event_len; i++) {
    HwangsaeHostInfo *info = NULL;

    guint8 *payload = NULL;
    gint payload_size, option_len;
    gint len;

    info = hwangsae_relay_map_get_info_by_sock (self->map, sink_events[i].fd);

    g_debug ("extract sink stream-id (%s) from sock", info->stream_id);

    switch (srt_getsockstate (sink_events[i].fd)) {
      case SRTS_BROKEN:
      case SRTS_NONEXIST:
      case SRTS_CLOSED:
        g_warning ("Invalid SRT sink socket (0x%x)", sink_events[i].fd);

        srt_epoll_remove_usock (self->sink_poll_id, sink_events[i].fd);
        srt_close (sink_events[i].fd);

        goto out;

      case SRTS_CONNECTED:
        /* good to go */
        break;
      default:
        /* not-ready */
        goto out;
    }

    if (srt_getsockflag (sink_events[i].fd, SRTO_PAYLOADSIZE, &payload_size,
            &option_len)) {
      g_error ("%s", srt_getlasterror_str ());
      goto out;
    }

    payload = g_alloca (payload_size + 1);
    if ((len =
            srt_recvmsg (sink_events[i].fd, (char *) payload,
                payload_size)) > 0) {
      _relay_to (self, info->stream_id, payload, len);
    }
  }

out:

  if (sink_events != NULL) {
    g_free (sink_events);
  }

  return G_SOURCE_CONTINUE;
}

static gpointer
_relay_main (gpointer data)
{
  HwangsaeRelay *self = data;
  g_autoptr (GSource) source = NULL;

  g_main_context_push_thread_default (self->context);

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) _main_loop_running_cb, self,
      NULL);
  g_source_attach (source, self->context);

  self->sink_poll_id = srt_epoll_create ();
  /* sink listener */
  self->sink_listen_sock = _srt_open_listen_sock (self->sink_port, 2);
  srt_listen_callback (self->sink_listen_sock,
      (srt_listen_callback_fn *) _sink_listen_cb, self);

  /* source listener */
  /* FIXME: 3k connections is realistic? */
  self->source_listen_sock = _srt_open_listen_sock (self->source_port, 3000);
  srt_listen_callback (self->source_listen_sock,
      (srt_listen_callback_fn *) _source_listen_cb, self);

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) _relay_running_cb, self, NULL);
  g_source_attach (source, self->context);

  g_debug ("Starting main loop");
  g_main_loop_run (self->loop);
  g_debug ("Stopped main loop");

  if (self->sink_listen_sock != SRT_INVALID_SOCK) {
    srt_close (self->sink_listen_sock);
    self->sink_listen_sock = SRT_INVALID_SOCK;
  }

  if (self->source_listen_sock != SRT_INVALID_SOCK) {
    srt_close (self->source_listen_sock);
    self->source_listen_sock = SRT_INVALID_SOCK;
  }

  srt_epoll_release (self->sink_poll_id);

  g_main_context_pop_thread_default (self->context);

  return NULL;
}

static void
hwangsae_relay_constructed (GObject * object)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);

  g_mutex_lock (&self->lock);
  self->thread = g_thread_new ("HwangsaeRelay", _relay_main, self);
  while (!self->loop || !g_main_loop_is_running (self->loop))
    g_cond_wait (&self->cond, &self->lock);
  g_mutex_unlock (&self->lock);

  G_OBJECT_CLASS (hwangsae_relay_parent_class)->constructed (object);
}

static void
hwangsae_relay_class_init (HwangsaeRelayClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->constructed = hwangsae_relay_constructed;
  gobject_class->set_property = hwangsae_relay_set_property;
  gobject_class->get_property = hwangsae_relay_get_property;
  gobject_class->dispose = hwangsae_relay_dispose;
  gobject_class->finalize = hwangsae_relay_finalize;

  g_object_class_install_property (gobject_class, PROP_SINK_PORT,
      g_param_spec_uint ("sink-port", "SRT Binding port (from) ",
          "SRT Binding port (from)", 0, G_MAXUINT, 8888,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_SOURCE_PORT,
      g_param_spec_uint ("source-port", "SRT Binding port (to) ",
          "SRT Binding port (to)", 0, G_MAXUINT, 9999,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
hwangsae_relay_init (HwangsaeRelay * self)
{
  if (g_atomic_int_get (&hwangsae_relay_init_refcnt) == 0) {
    if (srt_startup () != 0) {
      g_error ("%s", srt_getlasterror_str ());
    }
  }
  g_mutex_init (&self->lock);
  g_cond_init (&self->cond);

  self->sink_listen_sock = SRT_INVALID_SOCK;
  self->source_listen_sock = SRT_INVALID_SOCK;

  self->context = g_main_context_new ();
  self->loop = g_main_loop_new (self->context, FALSE);

  self->settings = g_settings_new ("org.hwangsaeul.hwangsae.relay");

  g_settings_bind (self->settings, "sink-port", self, "sink-port",
      G_SETTINGS_BIND_DEFAULT);
  g_settings_bind (self->settings, "source-port", self, "source-port",
      G_SETTINGS_BIND_DEFAULT);

  self->map = hwangsae_relay_map_new ();
}

HwangsaeRelay *
hwangsae_relay_new (void)
{
  return g_object_new (HWANGSAE_TYPE_RELAY, NULL);
}

static gchar *
_get_relayinfo_json_string (HwangsaeRelay * self, const gchar * stream_id,
    HwangsaeSRTMode mode, const gchar * srt_uri, HwangsaeDirection direction)
{
  g_autofree gchar *json_string = NULL;
  guint port =
      mode == HWANGSAE_SRT_MODE_CALLER ? 0 : direction ==
      HWANGSAE_DIRECTION_SINK ? self->sink_port : self->source_port;

  json_string =
      g_strdup_printf (RELAYINFO_JSON_FORMAT,
      stream_id == NULL ? "default" : stream_id, mode,
      srt_uri == NULL ? "" : srt_uri, port, direction);

  return g_steal_pointer (&json_string);
}

guint
hwangsae_relay_add_sink (HwangsaeRelay * self,
    const gchar * stream_id, HwangsaeSRTMode mode, const gchar * srt_uri,
    GError ** error)
{
  guint sink_id = 0;
  g_autofree gchar *relayinfo = NULL;

  g_return_val_if_fail (HWANGSAE_IS_RELAY (self), 0);
  g_return_val_if_fail (mode == HWANGSAE_SRT_MODE_CALLER && srt_uri != NULL, 0);
  g_return_val_if_fail (error == NULL || *error == NULL, 0);

  relayinfo =
      _get_relayinfo_json_string (self, stream_id, mode, srt_uri,
      HWANGSAE_DIRECTION_SINK);

  g_debug ("adding sink with (%s)", relayinfo);
  sink_id = g_str_hash (relayinfo);

  return sink_id;
}

guint
hwangsae_relay_add_source (HwangsaeRelay * self,
    const gchar * stream_id,
    HwangsaeSRTMode mode, guint sink_id, GError ** error)
{
  guint source_id;

  g_return_val_if_fail (HWANGSAE_IS_RELAY (self), 0);

  return source_id;
}

void
hwangsae_relay_remove (HwangsaeRelay * self, HwangsaeDirection direction,
    guint relay_id)
{
  g_return_if_fail (HWANGSAE_IS_RELAY (self));
  g_return_if_fail (relay_id != 0);
}
