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

#include <gio/gio.h>
#include <srt.h>

#include "relay-internal.h"

typedef struct _SRTInfo
{
  gint refcount;

  GSocketAddress *sockaddr;
  HwangsaeSRTMode mode;
  HwangsaeDirection direction;

  SRTSOCKET sock;

} SRTInfo;

static SRTInfo *
srt_info_new (GSocketAddress * sockaddr, SRTSOCKET sock, HwangsaeSRTMode mode,
    HwangsaeDirection direction)
{
  SRTInfo *info = g_new (SRTInfo, 1);

  info->refcount = 1;
  info->sockaddr = g_object_ref (sockaddr);
  info->sock = sock;
  info->mode = mode;
  info->direction = direction;

  return info;
}

static void
srt_info_unref (SRTInfo * info)
{
  if (g_atomic_int_dec_and_test (&info->refcount)) {

    g_clear_object (&info->sockaddr);

    if (info->sock != SRT_INVALID_SOCK) {
      srt_close (info->sock);
    }

    g_free (info);
  }
}

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
  gint source_poll_id;

  GHashTable *relay_map;
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
#if 0
  /* TODO: All SRT stream in Hwangsaeul Ecosystem must enable stream id */
  {"SRTO_STREAMID", SRTO_STREAMID, 1},  /* 1: enable stream id */
#endif
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
      g_thread_unref (self->thread);
    self->thread = NULL;

    g_main_loop_unref (self->loop);
    self->loop = NULL;

    g_main_context_unref (self->context);
    self->context = NULL;
  }

  g_clear_object (&self->settings);

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

static gint
_sink_listen_cb (HwangsaeRelay * self, SRTSOCKET sock, gint hs_version,
    const struct sockaddr *peeraddr, const gchar * stream_id)
{
  g_autoptr (GSocketAddress) addr = NULL;
  g_autofree gchar *addr_str = NULL;
  GInetAddress *inet_addr;

  SRTInfo *info = NULL;

  addr =
      g_socket_address_new_from_native ((gpointer) peeraddr,
      sizeof (struct sockaddr));
  inet_addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
  addr_str = g_inet_address_to_string (inet_addr);

  g_debug ("sink port: connection from [%s:%" G_GUINT16_FORMAT
      "], stream-id: %s", addr_str,
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)), stream_id);

  _apply_socket_options (sock);
  if (srt_setsockflag (sock, SRTO_SENDER, &(gint) {
          0}
          , sizeof (gint))) {
    goto srt_failed;
  }

  info =
      srt_info_new (addr, sock, HWANGSAE_SRT_MODE_CALLER,
      HWANGSAE_DIRECTION_SINK);

  return 0;                     /* connection accepted */

srt_failed:

  g_error ("%s", srt_getlasterror_str ());

  srt_close (sock);
  if (info != NULL)
    srt_info_unref (info);

  return -1;                    /* error */
}

static gint
_source_listen_cb (HwangsaeRelay * self, SRTSOCKET sock, gint hs_version,
    const struct sockaddr *peeraddr, const gchar * stream_id)
{
  g_autoptr (GSocketAddress) addr = NULL;
  g_autofree gchar *addr_str = NULL;
  GInetAddress *inet_addr;

  SRTInfo *info = NULL;

  addr =
      g_socket_address_new_from_native ((gpointer) peeraddr,
      sizeof (struct sockaddr));
  inet_addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
  addr_str = g_inet_address_to_string (inet_addr);

  g_debug ("source port: connection from [%s:%" G_GUINT16_FORMAT
      "], stream-id: %s", addr_str,
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)), stream_id);

  _apply_socket_options (sock);
  if (srt_setsockflag (sock, SRTO_SENDER, &(gint) {
          1}
          , sizeof (gint))) {
    goto srt_failed;
  }

  info =
      srt_info_new (addr, sock, HWANGSAE_SRT_MODE_CALLER,
      HWANGSAE_DIRECTION_SOURCE);

  return 0;                     /* connection accepted */

srt_failed:

  g_error ("%s", srt_getlasterror_str ());

  srt_close (sock);
  if (info != NULL)
    srt_info_unref (info);

  return -1;                    /* error */
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
  self->source_poll_id = srt_epoll_create ();
  /* sink listener */
  self->sink_listen_sock = _srt_open_listen_sock (self->sink_port, 1);
  srt_listen_callback (self->sink_listen_sock,
      (srt_listen_callback_fn *) _sink_listen_cb, self);

  /* source listener */
  /* FIXME: 3k connections is realistic? */
  self->source_listen_sock = _srt_open_listen_sock (self->source_port, 3000);
  srt_listen_callback (self->source_listen_sock,
      (srt_listen_callback_fn *) _source_listen_cb, self);

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
  srt_epoll_release (self->source_poll_id);

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

//  self->relay_map = g_hash_table_new_full ();
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
