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
#include "relay-internal.h"

#include <srt.h>
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

  GSource *relay_source;
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

typedef struct
{
  GSource source;
  gint poll_id;
  guint n_sock;

  SRT_EPOLL_EVENT *events;
} HwangsaeRelaySource;

static void
hwangsae_relay_source_add_sock (GSource * source, SRTSOCKET sock, gint flag)
{
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;
  if (srt_epoll_add_usock (relay_source->poll_id, sock, &flag)) {
    g_error ("%s", srt_getlasterror_str ());
  }

  relay_source->n_sock = 1;
}

static void
hwangsae_relay_source_remove_sock (GSource * source, SRTSOCKET sock)
{
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;

  srt_epoll_remove_usock (relay_source->poll_id, sock);
  relay_source->n_sock = 0;
}


static gboolean
hwangsae_relay_source_prepare (GSource * source, gint * timeout)
{
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;
  gboolean ret = FALSE;

  if (relay_source->poll_id == SRT_ERROR) {
    goto out;
  }

  if (relay_source->n_sock < 1) {
    goto out;
  }
  relay_source->events = g_new0 (SRT_EPOLL_EVENT, relay_source->n_sock);

  if (srt_epoll_uwait (relay_source->poll_id, relay_source->events,
          relay_source->n_sock, 100) < 0) {
    g_error ("%s", srt_getlasterror_str ());
    goto out;
  }
  ret = TRUE;

out:

  if (!ret) {
    g_clear_pointer (&relay_source->events, g_free);
    *timeout = 100;
  }

  return ret;
}

static gboolean
hwangsae_relay_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;
  gchar buffer[1024] = { 0 };
  gint i = 0;
  gint len = 0;
  for (; i < relay_source->n_sock; i++) {
    switch (srt_getsockstate (relay_source->events[i].fd)) {
      case SRTS_BROKEN:
      case SRTS_NONEXIST:
      case SRTS_CLOSED:
        g_warning ("Invalid SRT socket");
        hwangsae_relay_source_remove_sock (relay_source,
            relay_source->events[i].fd);
        srt_close (relay_source->events[i].fd);
        break;
      default:
        break;
    }
    do {
      len = srt_recvmsg (relay_source->events[i].fd, buffer, 1316);
      g_debug ("recv %d", len);
    } while (len > 0);
  }

  g_clear_pointer (&relay_source->events, g_free);


  return G_SOURCE_CONTINUE;
}

static void
hwangsae_relay_source_finalize (GSource * source)
{
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;
  g_debug ("source finalized");

  srt_epoll_release (relay_source->poll_id);
}

static GSource *
hwangsae_relay_source_new (void)
{
  static GSourceFuncs source_funcs = {
    hwangsae_relay_source_prepare,
    NULL,
    hwangsae_relay_source_dispatch,
    hwangsae_relay_source_finalize
  };

  GSource *source = g_source_new (&source_funcs, sizeof (HwangsaeRelaySource));
  HwangsaeRelaySource *relay_source = (HwangsaeRelaySource *) source;
  relay_source->poll_id = srt_epoll_create ();

  return source;
}

static void
hwangsae_relay_dispose (GObject * object)
{
  HwangsaeRelay *self = HWANGSAE_RELAY (object);

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
  g_autofree gchar *valid_stream_id = NULL;
  GInetAddress *inet_addr;
  g_autoptr (GSource) source = NULL;

  addr =
      g_socket_address_new_from_native ((gpointer) peeraddr,
      sizeof (struct sockaddr));
  inet_addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
  addr_str = g_inet_address_to_string (inet_addr);

  valid_stream_id =
      stream_id != NULL
      && *stream_id != '\0' ? g_strdup (stream_id) : g_strdup ("default");

  g_debug ("accepting a sink connection from [%s:%" G_GUINT16_FORMAT
      "], stream-id: %s (sock: 0x%x)", addr_str,
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)),
      valid_stream_id, sock);

  _apply_socket_options (sock);

  if (srt_setsockflag (sock, SRTO_SENDER, &(gint) {
          0}
          , sizeof (gint))) {
    g_error ("%s", srt_getlasterror_str ());
    goto reject;
  }

  hwangsae_relay_source_add_sock (self->relay_source, sock,
      (SRT_EPOLL_ERR | SRT_EPOLL_IN));

  /* TODO: need to set passphrase from external key management system */
  if (srt_setsockflag (sock, SRTO_PASSPHRASE, "123456789!", 10)) {
    g_error ("%s", srt_getlasterror_str ());
    goto reject;
  }

  return 0;

reject:

  g_warning ("reject connection request (stream-id: %s, sock: 0x%x)",
      valid_stream_id, sock);
  srt_close (sock);

  return -1;
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

  self->relay_source = hwangsae_relay_source_new ();
  g_source_set_callback (self->relay_source, NULL, self, NULL);
  g_source_attach (self->relay_source, self->context);

  /* sink listener */
  self->sink_listen_sock = _srt_open_listen_sock (self->sink_port, 1);
  srt_listen_callback (self->sink_listen_sock,
      (srt_listen_callback_fn *) _sink_listen_cb, self);

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
    srt_setloglevel (LOG_NOTICE);
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
}

HwangsaeRelay *
hwangsae_relay_new (void)
{
  return g_object_new (HWANGSAE_TYPE_RELAY, NULL);
}
