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

#ifndef __HWANGSAE_RELAY_H__
#define __HWANGSAE_RELAY_H__

#if !defined(__HWANGSAE_INSIDE__) && !defined(HWANGSAE_COMPILATION)
#error "Only <hwangsae/hwangsae.h> can be included directly."
#endif

#include <hwangsae/types.h>

#include <glib-object.h>

G_BEGIN_DECLS

#define HWANGSAE_TYPE_RELAY     (hwangsae_relay_get_type ())
G_DECLARE_FINAL_TYPE            (HwangsaeRelay, hwangsae_relay, HWANGSAE, RELAY, GObject)


HwangsaeRelay          *hwangsae_relay_new              (void);

guint                   hwangsae_relay_add_sink         (HwangsaeRelay     *self,
                                                         const gchar       *stream_id,
                                                         HwangsaeSRTMode    mode,
                                                         const gchar       *srt_uri,
                                                         GError           **error);

guint                   hwangsae_relay_add_source       (HwangsaeRelay     *self,
                                                         const gchar       *stream_id,
                                                         HwangsaeSRTMode    mode,
                                                         guint              sink_id,
                                                         GError           **error);

void                   hwangsae_relay_remove            (HwangsaeRelay     *self,
                                                         HwangsaeDirection  direction,
                                                         guint              relay_id); 

G_END_DECLS

#endif // __HWANGSAE_RELAY_H__

