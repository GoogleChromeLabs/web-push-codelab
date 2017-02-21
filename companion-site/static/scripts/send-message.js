/* eslint-env browser,  es6 */

function getDetails() {
  const details = window.localStorage.getItem('last-known-details');
  try {
    if (details) {
      return JSON.parse(details);
    }
  } catch (err) {
    // NOOP
  }
  return null;
}

function saveDetails(details) {
  window.localStorage.setItem('last-known-details',
    JSON.stringify(details));
}

function sendPushMessage() {
  const subscriptionTextArea = document.querySelector('#push-subscription');
  const textToSendTextArea = document.querySelector('#push-data');

  const subscriptionString = subscriptionTextArea.value.trim();
  const dataString = textToSendTextArea.value;

  saveDetails({
    subscription: subscriptionString,
    data: dataString
  });

  if (subscriptionString.length === 0 ) {
    return Promise.reject(new Error('Please provide a push subscription.'));
  }

  let subscriptionObject = null;
  try {
    subscriptionObject = JSON.parse(subscriptionString);
  } catch (err) {
    return Promise.reject(new Error('Unable to parse subscription as JSON'));
  }

  if (!subscriptionObject.endpoint) {
    return Promise.reject(new Error('The subscription MUST have an endpoint'));
  }

  if (subscriptionObject.endpoint.indexOf('…') !== -1) {
    return Promise.reject(new Error('The subscription endpoint appears to be ' +
      'truncated (It has \'...\' in it).\n\nDid you copy it from the console ' +
      'in Chrome?')
    );
  }

  const publicElement = document.querySelector('.js-public-key');
  const privateElement = document.querySelector('.js-private-key');

  return fetch('/api/send-push-msg', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      subscription: subscriptionObject,
      data: dataString,
      applicationKeys: {
        public: publicElement.textContent,
        private: privateElement.textContent,
      }
    })
  })
  .then((response) => {
    if (response.status !== 200) {
      return response.text()
      .then((responseText) => {
        throw new Error(responseText);
      });
    }
  });
}

function initialiseUI() {
  const sendBtn = document.querySelector('.js-send-push');
  sendBtn.addEventListener('click', () => {
    sendBtn.disabled = true;

    sendPushMessage()
    .catch((err) => {
      console.error(err);
      window.alert(err.message);
    })
    .then(() => {
      sendBtn.disabled = false;
    });
  });

  const previousDetails = getDetails();
  if (previousDetails) {
    const subscriptionTextArea = document.querySelector('#push-subscription');
    const textToSendTextArea = document.querySelector('#push-data');

    subscriptionTextArea.value = previousDetails.subscription;
    textToSendTextArea.value = previousDetails.data;
  }

  sendBtn.disabled = false;
}

window.addEventListener('load', () => {
  initialiseUI();
});
