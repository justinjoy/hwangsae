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

#include <glib-unix.h>
#include <gio/gio.h>
#include <srt.h>

typedef gboolean (*HwangsaeSinkSourceFunc) (gint socket, gpointer user_data);

typedef struct
{
  GSource source;
  gint sock;
} HwangsaeSinkSource;

static gboolean
hwangsae_sink_source_prepare (GSource * source, gint * timeout)
{
  *timeout = 100;
  g_debug ("prepare");
  return FALSE;
}

static gboolean
hwangsae_sink_source_check (GSource * source)
{
  g_debug ("check");
  return TRUE;
}

static gboolean
hwangsae_sink_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  gboolean keep = FALSE;
  HwangsaeSinkSource *sink_source = (HwangsaeSinkSource *) source;
  HwangsaeSinkSourceFunc handler = (HwangsaeSinkSourceFunc) callback;

  keep = handler (sink_source->sock, user_data);

  return keep;
}

static GSource *
hwangsae_sink_source_new (gint socket)
{
  static GSourceFuncs source_funcs = {
    hwangsae_sink_source_prepare,
    hwangsae_sink_source_check,
    hwangsae_sink_source_dispatch,
    NULL,
  };

  GSource *source = g_source_new (&source_funcs, sizeof (HwangsaeSinkSource));
  HwangsaeSinkSource *sink_source = (HwangsaeSinkSource *) source;
  sink_source->sock = socket;

  return source;
}

guint
hwangsae_sink_source_add_watch (gint socket, HwangsaeSinkSourceFunc callback,
    gpointer data)
{
  g_autoptr (GSource) source = NULL;

  source = hwangsae_sink_source_new (socket);

  g_source_set_callback (source, (GSourceFunc) callback, data, NULL);

  return g_source_attach (source, NULL);
}

static gboolean
sink_cb (gint socket, gpointer data)
{
  g_debug ("run %d", socket);

  return G_SOURCE_CONTINUE;
}

static void
activate (GApplication * app, gpointer user_data)
{
  g_application_hold (app);

  hwangsae_sink_source_add_watch (10, sink_cb, app);
}

static gboolean
intr_handler (gpointer user_data)
{
  GApplication *app = user_data;
  g_application_release (app);
  return G_SOURCE_REMOVE;
}

int
main (int argc, char *argv[])
{
  g_autoptr (GApplication) app =
      g_application_new ("org.hwangsaeul.Hwangsae1.RelayApp", 0);

  g_unix_signal_add (SIGINT, (GSourceFunc) intr_handler, app);
  g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);

  return g_application_run (app, argc, argv);
}
