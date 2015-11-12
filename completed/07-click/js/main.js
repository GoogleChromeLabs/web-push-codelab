/*
*
*  Push Notifications codelab
*  Copyright 2015 Google Inc. All rights reserved.
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      https://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License
*
*/

'use strict';

if ('serviceWorker' in navigator) {
  console.log('Service Worker is supported');
  navigator.serviceWorker.register('sw.js').then(function() {
    return navigator.serviceWorker.ready;
  }).then(function(reg) {
    console.log('Service Worker is ready :^)', reg);
    reg.pushManager.subscribe({userVisibleOnly: true}).then(function(sub) {
      console.log('endpoint:', sub.endpoint);
    });
  }).catch(function(error) {
    console.log('Service Worker error :^(', error);
  });
}
