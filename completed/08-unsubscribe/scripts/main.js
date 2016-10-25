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

/* eslint-env browser, es6 */

'use strict';

/* eslint-disable max-len */
const applicationServerPublicKey = 'BH8-hIchXKMI6AKSee8gD0hhPThRqaEhIEtMJwcTjEQhiOKdG-_2tTIO-6hOAK4kwg5M9Saedjxp4hVE-khhWxY';
/* eslint-enable max-len */

// IMPORTANT: You should NEVER share you application servers private key.
// We are doing it here to simplify the code lab.
/* eslint-disable max-len */
const applicationServerPriveKey = 'Ev-QDJE7KPAkM2tu023PW_GCYpXNjL-r13fV53gPJRM';
/* eslint-end max-len */

// IMPORTANT: You should NEVER share you GCM API key.
// We are doing it here to simplify the code lab.
const gcmApiKey = '';

const pushButton = document.querySelector('.js-push-btn');
const pushCLI = document.querySelector('.js-web-push-cli');

let isSubscribed = false;
let swRegistration = null;

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function updateBtn() {
  if (Notification.permission === 'denied') {
    pushButton.textContent = 'Push Messaging Blocked.';
    pushButton.disabled = true;
    return;
  }

  if (isSubscribed) {
    pushButton.textContent = 'Disable Push Messaging';
  } else {
    pushButton.textContent = 'Enable Push Messaging';
  }

  pushButton.disabled = false;
}

function sendToServer(subscription) {
  const jsonString = JSON.stringify(subscription);
  console.log('Subscription as JSON String: ', jsonString);

  // On the server this would then be parsed and the values used.
  // Notice that the keys are now base64 url encoded.
  const parsedSubscription = JSON.parse(jsonString);


  const values = [
    `--endpoint ${parsedSubscription.endpoint}`,
    `--auth ${parsedSubscription.keys.auth}`,
    `--key ${parsedSubscription.keys.p256dh}`,
    `--vapid-subject https://developers.google.com/web/push-codelab/`,
    `--vapid-pubkey ${applicationServerPublicKey}`,
    `--vapid-pvtkey ${applicationServerPriveKey}`,
  ];

  if (gcmApiKey && gcmApiKey.length > 0) {
    values.push(`--gcm-api-key ${gcmApiKey}`);
  }

  pushCLI.textContent = `web-push send-notification ${values.join(' ')}`;
}

function subscribeUser() {
  swRegistration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(applicationServerPublicKey)
  })
  .then(function(subscription) {
    console.log('Subscribed:', subscription);

    sendToServer(subscription);

    isSubscribed = true;
  })
  .then(function() {
    updateBtn();
  })
  .catch(function(err) {
    console.log(err);
    updateBtn();
  });
}

function unsubscribeUser() {
  swRegistration.pushManager.getSubscription()
  .then(function(subscription) {
    if (subscription) {
      return subscription.unsubscribe();
    }
  })
  .catch(function(error) {
    console.log('Error unsubscribing', error);
  })
  .then(function() {
    isSubscribed = false;
    pushCLI.textContent = '';

    updateBtn();
  });
}

function initialiseUI() {
  pushButton.addEventListener('click', function() {
    pushButton.disabled = true;
    if (isSubscribed) {
      unsubscribeUser();
    } else {
      subscribeUser();
    }
  });

  // Set the initial subscription value
  swRegistration.pushManager.getSubscription()
  .then(function(subscription) {
    isSubscribed = !(subscription === null);

    if (isSubscribed) {
      sendToServer(subscription);
    }

    updateBtn();
  });
}

if ('serviceWorker' in navigator && 'PushManager' in window) {
  console.log('Service Worker and Push is supported');

  navigator.serviceWorker.register('sw.js')
  .then(function(swReg) {
    console.log('Service Worker is registered');

    swRegistration = swReg;
    initialiseUI();
  })
  .catch(function(error) {
    console.error('Service Worker Error', error);
  });
} else {
  console.warn('Push messaging is not supported');
  pushButton.textContent = 'Push Not Supported';
}
