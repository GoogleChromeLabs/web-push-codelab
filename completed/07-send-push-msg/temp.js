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
