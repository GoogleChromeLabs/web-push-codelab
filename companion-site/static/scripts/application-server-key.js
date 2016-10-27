/* eslint-env browser, es6 */

function base64UrlToUint8Array(base64UrlData) {
  const padding = '='.repeat((4 - base64UrlData.length % 4) % 4);
  const base64 = (base64UrlData + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const buffer = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    buffer[i] = rawData.charCodeAt(i);
  }
  return buffer;
}

function uint8ArrayToBase64Url(uint8Array, start, end) {
  start = start || 0;
  end = end || uint8Array.byteLength;

  const base64 = window.btoa(
    String.fromCharCode.apply(null, uint8Array.subarray(start, end)));
  return base64
    .replace(/\=/g, '') // eslint-disable-line no-useless-escape
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function cryptoKeyToUrlBase64(publicKey, privateKey) {
  const promises = [];
  promises.push(
    crypto.subtle.exportKey('jwk', publicKey)
    .then((jwk) => {
      const x = base64UrlToUint8Array(jwk.x);
      const y = base64UrlToUint8Array(jwk.y);

      const publicKey = new Uint8Array(65);
      publicKey.set([0x04], 0);
      publicKey.set(x, 1);
      publicKey.set(y, 33);

      return publicKey;
    })
  );

  promises.push(
    crypto.subtle
      .exportKey('jwk', privateKey)
    .then((jwk) => {
      return base64UrlToUint8Array(jwk.d);
    })
  );

  return Promise.all(promises)
  .then((exportedKeys) => {
    return {
      public: uint8ArrayToBase64Url(exportedKeys[0]),
      private: uint8ArrayToBase64Url(exportedKeys[1]),
    };
  });
}

function generateNewKeys() {
  return crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'},
    true, ['deriveBits'])
  .then((keys) => {
    return cryptoKeyToUrlBase64(keys.publicKey, keys.privateKey);
  });
}

function clearKeys() {
  window.localStorage.removeItem('server-keys');
}

function storeKeys(keys) {
  window.localStorage.setItem('server-keys', JSON.stringify(keys));
}

function getStoredKeys() {
  const storage = window.localStorage.getItem('server-keys');
  if (storage) {
    return JSON.parse(storage);
  }

  return null;
}

function displayKeys(keys) {
  const publicElement = document.querySelector('.js-public-key');
  const privateElement = document.querySelector('.js-private-key');
  const refreshBtn = document.querySelector('.js-refresh-keys');

  publicElement.textContent = keys.public;
  privateElement.textContent = keys.private;

  refreshBtn.disabled = false;
}

function updateKeys() {
  let storedKeys = getStoredKeys();
  let promiseChain = Promise.resolve(storedKeys);
  if (!storedKeys) {
    promiseChain = generateNewKeys()
    .then((newKeys) => {
      storeKeys(newKeys);
      return newKeys;
    });
  }

  return promiseChain.then((keys) => {
    displayKeys(keys);
  });
}

function initialiseKeys() {
  const refreshBtn = document.querySelector('.js-refresh-keys');
  refreshBtn.addEventListener('click', function() {
    refreshBtn.disabled = true;

    clearKeys();

    updateKeys();
  });

  updateKeys();
}

window.addEventListener('load', () => {
  initialiseKeys();
});
