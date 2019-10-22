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

#ifndef __HWNAGSAE_RELAY_INTERNAL_H__
#define __HWNAGSAE_RELAY_INTERNAL_H__

#define RELAYINFO_JSON_FORMAT \
"{ \
   \"stream-id\": \"%s\", \
   \"mode\": %" G_GINT32_FORMAT ", \
   \"uri\": \"%s\", \
   \"port\": %" G_GUINT32_FORMAT ", \
   \"direction\": %" G_GINT32_FORMAT " \
}"

#endif // __HWNAGSAE_RELAY_INTERNAL_H__
