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

#include "host-info.h"
#include <gmodule.h>

/* *INDENT-OFF* */
G_DEFINE_BOXED_TYPE (HwangsaeHostInfo, hwangsae_host_info,
                     hwangsae_host_info_ref,
                     hwangsae_host_info_unref)
/* *INDENT-ON* */

HwangsaeHostInfo *
hwangsae_host_info_new (GSocketAddress * sockaddr, const gchar * stream_id,
    SRTSOCKET sock, gint handshake_version, HwangsaeSRTMode mode,
    HwangsaeDirection direction)
{
  HwangsaeHostInfo *info = g_new (HwangsaeHostInfo, 1);

  info->refcount = 1;
  info->sockaddr = g_object_ref (sockaddr);
  info->stream_id = g_strdup (stream_id);
  info->sock = sock;
  info->mode = mode;
  info->direction = direction;
  info->handshake_version = handshake_version;

  if (direction == HWANGSAE_DIRECTION_SINK) {
    info->src_poll_id = srt_epoll_create ();
  } else {
    info->src_poll_id = SRT_ERROR;
  }

  g_debug ("host info created (ref: %d)", info->refcount);
  return info;
}

HwangsaeHostInfo *
hwangsae_host_info_ref (HwangsaeHostInfo * info)
{
  g_return_val_if_fail (info != NULL, NULL);
  g_return_val_if_fail (info->stream_id != NULL, NULL);
  g_return_val_if_fail (info->refcount >= 1, NULL);

  g_atomic_int_inc (&info->refcount);
  g_debug ("host info ref (ref: %d)", info->refcount);

  return info;
}

void
hwangsae_host_info_unref (HwangsaeHostInfo * info)
{
  g_return_if_fail (info != NULL);
  g_return_if_fail (info->stream_id != NULL);
  g_return_if_fail (info->refcount >= 1);

  g_debug ("unref host info (refcount: %d)", info->refcount);
  if (g_atomic_int_dec_and_test (&info->refcount)) {
    g_debug ("freeing host info (stream-id: %s, sock: 0x%x)", info->stream_id,
        info->sock);
    g_clear_object (&info->sockaddr);

    if (info->sock != SRT_INVALID_SOCK) {
      g_debug ("close srt socket");
      srt_close (info->sock);
    }
    if (info->direction == HWANGSAE_DIRECTION_SINK
        && info->src_poll_id != SRT_ERROR) {
      srt_epoll_release (info->src_poll_id);
    }

    g_free (info->stream_id);
    g_free (info);
  }
}
