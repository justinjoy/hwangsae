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

#include "relay-map.h"
#include "host-info.h"

#include <gmodule.h>

struct _HwangsaeRelayMap
{
  gint refcount;
  GHashTable *id_map;           /* (element-type utf8 HwangsaeHostInfo *) */
  GHashTable *sock_map;         /* (element-type SRTSOCKET HwangsaeHostInfo *) */

  GHashTable *sink_src_id_map;  /* (element-type utf8 GLib.Sequence(utf8)) */
  GHashTable *src_sink_id_map;  /* (element-type utf8 utf8) */
};

/* *INDENT-OFF* */
G_DEFINE_BOXED_TYPE (HwangsaeRelayMap, hwangsae_relay_map,
                     hwangsae_relay_map_ref,
                     hwangsae_relay_map_unref)
/* *INDENT-ON* */

HwangsaeRelayMap *
hwangsae_relay_map_new (void)
{
  HwangsaeRelayMap *map = g_new0 (HwangsaeRelayMap, 1);

  map->refcount = 1;

  map->id_map = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) hwangsae_host_info_unref);

  map->sock_map = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
      (GDestroyNotify) hwangsae_host_info_unref);

  map->sink_src_id_map = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) g_sequence_free);

  map->src_sink_id_map =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return map;
}

HwangsaeRelayMap *
hwangsae_relay_map_ref (HwangsaeRelayMap * map)
{
  g_return_val_if_fail (map != NULL, NULL);
  g_return_val_if_fail (map->refcount >= 1, NULL);

  g_atomic_int_inc (&map->refcount);

  return map;
}

void
hwangsae_relay_map_unref (HwangsaeRelayMap * map)
{
  g_return_if_fail (map != NULL);
  g_return_if_fail (map->refcount >= 1);

  if (g_atomic_int_dec_and_test (&map->refcount)) {

    g_clear_pointer (&map->id_map, g_hash_table_destroy);
    g_clear_pointer (&map->sock_map, g_hash_table_destroy);
    g_clear_pointer (&map->sink_src_id_map, g_hash_table_destroy);
    g_clear_pointer (&map->src_sink_id_map, g_hash_table_destroy);

    g_free (map);
  }
}

HwangsaeHostInfo *
hwangsae_relay_map_add_sink (HwangsaeRelayMap * self,
    GSocketAddress * sockaddr,
    const gchar * stream_id,
    SRTSOCKET sink_sock, gint handshake_version, HwangsaeSRTMode mode)
{
  g_autoptr (HwangsaeHostInfo) info = NULL;

  g_return_val_if_fail (self != NULL, NULL);
  g_return_val_if_fail (stream_id != NULL && *stream_id != '\0', NULL);

  info =
      hwangsae_host_info_new (sockaddr, stream_id, sink_sock, handshake_version,
      mode, HWANGSAE_DIRECTION_SINK);

  /* check if stream-id is already existed */
  if (g_hash_table_lookup (self->id_map, stream_id) != NULL) {
    g_debug ("ignore sink due to stream id duplication (%s)", stream_id);
    return NULL;
  }

  g_hash_table_insert (self->id_map, g_strdup (stream_id),
      hwangsae_host_info_ref (info));
  g_hash_table_insert (self->sock_map, GINT_TO_POINTER (sink_sock),
      hwangsae_host_info_ref (info));
  g_hash_table_insert (self->sink_src_id_map, g_strdup (stream_id),
      g_sequence_new ((GDestroyNotify) hwangsae_host_info_unref));

  return g_steal_pointer (&info);
}

gboolean
hwangsae_relay_map_add_source (HwangsaeRelayMap * self,
    GSocketAddress * sockaddr,
    const gchar * sink_stream_id,
    const gchar * src_stream_id,
    SRTSOCKET source_sock, gint handshake_version, HwangsaeSRTMode mode)
{
  g_autoptr (HwangsaeHostInfo) info = NULL;
  HwangsaeHostInfo *sink_info = NULL;
  GSequence *src_ids = NULL;

  g_return_val_if_fail (self != NULL, FALSE);
  g_return_val_if_fail (sink_stream_id != NULL
      && *sink_stream_id != '\0', FALSE);

  sink_info = g_hash_table_lookup (self->id_map, sink_stream_id);

  if (sink_info == NULL) {
    g_debug ("can't find sink information by given id (%s)", sink_stream_id);
    return FALSE;
  }

  info =
      hwangsae_host_info_new (sockaddr, src_stream_id, source_sock,
      handshake_version, mode, HWANGSAE_DIRECTION_SOURCE);

  /* check if stream-id is already existed */
  if (g_hash_table_lookup (self->sock_map,
          GINT_TO_POINTER (source_sock)) != NULL) {
    g_debug ("ignore source due to socket duplication (0x%x)", source_sock);
    return FALSE;
  }

  src_ids = g_hash_table_lookup (self->sink_src_id_map, sink_stream_id);
  if (src_ids == NULL) {
    /* if id_map has sink stream id, sink_src_id_map should have too */
    g_assert_not_reached ();
  }

  g_sequence_append (src_ids, g_strdup (src_stream_id));

  g_hash_table_insert (self->id_map, g_strdup (src_stream_id),
      hwangsae_host_info_ref (info));
  g_hash_table_insert (self->sock_map, GINT_TO_POINTER (source_sock),
      hwangsae_host_info_ref (info));
  g_hash_table_insert (self->src_sink_id_map, g_strdup (src_stream_id),
      g_strdup (sink_stream_id));

  return TRUE;
}

HwangsaeHostInfo *
hwangsae_relay_map_get_info (HwangsaeRelayMap * self, const gchar * stream_id)
{
  g_return_val_if_fail (self != NULL, NULL);
  g_return_val_if_fail (stream_id != NULL && *stream_id != '\0', NULL);

  return g_hash_table_lookup (self->id_map, stream_id);
}

HwangsaeHostInfo *hwangsae_relay_map_get_info_by_sock
    (HwangsaeRelayMap * self, SRTSOCKET sock)
{
  g_return_val_if_fail (self != NULL, NULL);
  g_return_val_if_fail (sock != SRT_INVALID_SOCK, NULL);

  return g_hash_table_lookup (self->sock_map, GINT_TO_POINTER (sock));
}

static gboolean
_src_sink_remove_func (gpointer key, gpointer value, gpointer user_data)
{
  gchar *sink_stream_id = user_data;

  return g_strcmp0 (value, sink_stream_id) == 0;
}

static gboolean
_src_sock_remove_func (gpointer key, gpointer value, gpointer user_data)
{
  gchar *stream_id = user_data;
  HwangsaeHostInfo *info = value;

  return g_strcmp0 (info->stream_id, stream_id) == 0;
}

static gint
_src_id_cmp (gchar * a, gchar * b, gpointer data)
{
  return g_strcmp0 (a, b);
}

void
hwangsae_relay_map_remove_by_sock (HwangsaeRelayMap * self, SRTSOCKET sock)
{
  HwangsaeHostInfo *info = NULL;
  gchar *sink_stream_id = NULL;

  GSequence *src_ids = NULL;
  GSequenceIter *src_iter = NULL;

  g_return_if_fail (HWANGSAE_IS_RELAY_MAP (self));
  g_return_if_fail (sock != SRT_INVALID_SOCK);

  info = g_hash_table_lookup (self->sock_map, GINT_TO_POINTER (sock));
  if (info == NULL) {
    g_debug ("not found sock, ignored removing request (0x%x)", sock);
    return;
  }

  sink_stream_id = g_hash_table_lookup (self->src_sink_id_map, info->stream_id);

  src_ids = g_hash_table_lookup (self->sink_src_id_map, sink_stream_id);
  src_iter =
      g_sequence_lookup (src_ids, info->stream_id,
      (GCompareDataFunc) _src_id_cmp, NULL);
  g_sequence_remove (src_iter);

  g_hash_table_remove (self->sock_map, GINT_TO_POINTER (sock));
  g_hash_table_remove (self->src_sink_id_map, info->stream_id);
  g_hash_table_remove (self->id_map, info->stream_id);
}


void
hwangsae_relay_map_remove (HwangsaeRelayMap * self, const gchar * stream_id)
{
  HwangsaeHostInfo *info = NULL;
  GSequence *src_ids = NULL;
  GSequenceIter *src_iter = NULL;
  gchar *sink_stream_id = NULL;

  g_return_if_fail (self != NULL);
  g_return_if_fail (stream_id != NULL && *stream_id != '\0');

  info = g_hash_table_lookup (self->id_map, stream_id);

  if (info == NULL) {
    g_debug ("not found stream-id, ignored removing request (%s)", stream_id);
    return;
  }

  if (info->direction == HWANGSAE_DIRECTION_SOURCE) {
    hwangsae_relay_map_remove_by_sock (self, info->sock);
    return;
  }

  src_ids = g_hash_table_lookup (self->sink_src_id_map, sink_stream_id);
  src_iter = g_sequence_get_begin_iter (src_ids);

  while (!g_sequence_iter_is_end (src_iter)) {
    GSequenceIter *next = g_sequence_iter_next (src_iter);
    gchar *src_stream_id = g_sequence_get (src_iter);
    HwangsaeHostInfo *src_srt_info =
        g_hash_table_lookup (self->id_map, src_stream_id);

    g_hash_table_remove (self->sock_map, GINT_TO_POINTER (src_srt_info->sock));
    g_hash_table_remove (self->src_sink_id_map, src_srt_info->stream_id);
    g_hash_table_remove (self->id_map, src_srt_info->stream_id);

    g_sequence_remove (src_iter);
    src_iter = next;
  }
}

guint
hwangsae_relay_map_sink_count (HwangsaeRelayMap * self)
{
  return g_hash_table_size (self->sink_src_id_map);
}

GList *
hwangsae_relay_map_get_sink_ids (HwangsaeRelayMap * self)
{
  return g_hash_table_get_keys (self->sink_src_id_map);
}
