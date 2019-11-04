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

#ifndef __HWANGSAE_RELAY_MAP_H__
#define __HWANGSAE_RELAY_MAP_H__

#include <glib-object.h>
#include <gio/gio.h>

#include <srt.h>
#include <hwangsae/types.h>
#include <hwangsae/host-info.h>

G_BEGIN_DECLS

#define HWANGSAE_TYPE_RELAY_MAP         (hwangsae_relay_map_get_type ())
#define HWANGSAE_IS_RELAY_MAP(obj)      (G_TYPE_CHECK_INSTANCE_TYPE ((obj), HWANGSAE_TYPE_RELAY_MAP))

typedef struct _HwangsaeRelayMap        HwangsaeRelayMap;

GType hwangsae_relay_map_get_type       (void);

HwangsaeRelayMap       *hwangsae_relay_map_new          (void);

HwangsaeRelayMap       *hwangsae_relay_map_ref          (HwangsaeRelayMap *self);

void                    hwangsae_relay_map_unref        (HwangsaeRelayMap *self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (HwangsaeRelayMap, hwangsae_relay_map_unref)

HwangsaeHostInfo       *hwangsae_relay_map_add_sink     (HwangsaeRelayMap      *self,
                                                         GSocketAddress        *sockaddr,
                                                         const gchar           *stream_id,
                                                         SRTSOCKET              sink_sock,
                                                         gint                   handshake_version,
                                                         HwangsaeSRTMode        mode);

gboolean                hwangsae_relay_map_add_source   (HwangsaeRelayMap      *self,
                                                         GSocketAddress        *sockaddr,
                                                         const gchar           *sink_stream_id,
                                                         const gchar           *src_stream_id,
                                                         SRTSOCKET              source_sock,
                                                         gint                   handshake_version,
                                                         HwangsaeSRTMode        mode);

HwangsaeHostInfo       *hwangsae_relay_map_get_info     (HwangsaeRelayMap      *self,
                                                         const gchar           *stream_id);

HwangsaeHostInfo       *hwangsae_relay_map_get_info_by_sock
                                                        (HwangsaeRelayMap      *self,
                                                         SRTSOCKET              sock);

void                    hwangsae_relay_map_remove       (HwangsaeRelayMap      *self,
                                                         const gchar           *stream_id);

void                    hwangsae_relay_map_remove_by_sock
                                                        (HwangsaeRelayMap      *self,
                                                         SRTSOCKET              sock);

guint                   hwangsae_relay_map_sink_count   (HwangsaeRelayMap      *self);

GList                  *hwangsae_relay_map_get_sink_ids (HwangsaeRelayMap      *self);

G_END_DECLS

#endif //  __HWANGSAE_RELAY_MAP_H__
