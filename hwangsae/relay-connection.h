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

#ifndef __HWANGSAE_RELAY_CONNECTION_H__
#define __HWANGSAE_RELAY_CONNECTION_H__

#include <srt.h>
#include <glib-object.h>

G_BEGIN_DECLS

typedef gboolean        (*HwangsaeRelayFunc)            (SRTSOCKET sink_sock, gchar *stream_id,
                                                         guint8 *payload, gint len, gpointer user_data);

guint                   hwangsae_relay_connection_add_watch
                                                        (SRTSOCKET sink_sock,
                                                         HwangsaeRelayFunc callback,
                                                         gpointer user_data); 

G_END_DECLS

#endif // __HWANGSAE_RELAY_CONNECTION_H__
