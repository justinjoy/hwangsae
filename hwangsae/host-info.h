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

#ifndef __HWANGSAE_HOST_INFO_H__
#define __HWANGSAE_HOST_INFO_H__

#include <gio/gio.h>
#include <srt.h>

#include "types.h"

G_BEGIN_DECLS

#define HWANGSAE_TYPE_HOST_INFO         (hwangsae_host_info_get_type ())
#define HWANGSAE_IS_HOST_INFO(obj)      (G_TYPE_CHECK_INSTANCE_TYPE ((obj), HWANGSAE_TYPE_HOST_INFO))

GType hwangsae_host_info_get_type       (void);

typedef struct _HwangsaeHostInfo
{
  gint refcount;

  GSocketAddress *sockaddr;
  gchar *stream_id;
  HwangsaeSRTMode mode;
  HwangsaeDirection direction;
  gint handshake_version;

  SRTSOCKET sock;
  gint src_poll_id;

} HwangsaeHostInfo;

HwangsaeHostInfo       *hwangsae_host_info_new          (GSocketAddress        *sockaddr,
                                                         const gchar           *stream_id,
                                                         SRTSOCKET              sock,
                                                         gint                   handshake_version,
                                                         HwangsaeSRTMode        mode,
                                                         HwangsaeDirection      direction);

HwangsaeHostInfo       *hwangsae_host_info_ref          (HwangsaeHostInfo      *info);

void                    hwangsae_host_info_unref        (HwangsaeHostInfo      *info);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (HwangsaeHostInfo, hwangsae_host_info_unref)

G_END_DECLS

#endif // __HWANGSAE_HOST_INFO_H__
