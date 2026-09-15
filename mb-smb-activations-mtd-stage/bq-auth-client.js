// BQAuth client — drop this file into any *.telus.gizmos.run portal to get
// BigQuery access tokens for the signed-in user without owning an OAuth client.
//
//   const token = await BQAuth.getToken();   // call from a click handler
//   token.accessToken / token.email / token.name / token.expiresAt
//
// Opens a popup to the bq-auth broker only when there's no cached token.
// The token is the USER'S own (scope: bigquery.readonly) — BigQuery IAM
// still decides what they can read.

const BQAuth = (() => {
  const BROKER_URL = 'https://bq-auth.telus.gizmos.run';
  const CACHE_KEY = 'bq_auth_token';

  function parseIdToken(idToken) {
    const part = idToken.split('.')[1];
    const pad = part.length % 4 === 0 ? '' : '='.repeat(4 - (part.length % 4));
    const payload = JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/') + pad));
    return { email: payload.email ?? '', name: payload.name ?? payload.email ?? '' };
  }

  function cached() {
    try {
      const t = JSON.parse(sessionStorage.getItem(CACHE_KEY));
      if (t && t.accessToken && Date.now() < t.expiresAt) return t;
    } catch { /* fall through */ }
    return null;
  }

  function clear() {
    sessionStorage.removeItem(CACHE_KEY);
  }

  function getToken({ brokerUrl = BROKER_URL, force = false } = {}) {
    if (!force) {
      const t = cached();
      if (t) return Promise.resolve(t);
    }
    return new Promise((resolve, reject) => {
      const broker = new URL(brokerUrl).origin;
      const popup = window.open(
        `${broker}/?origin=${encodeURIComponent(location.origin)}`,
        'bq-auth',
        'width=480,height=640,popup=yes',
      );
      if (!popup) {
        reject(new Error('Popup blocked — call getToken() from a click handler'));
        return;
      }
      const closePoll = setInterval(() => {
        if (popup.closed) { cleanup(); reject(new Error('Sign-in was cancelled')); }
      }, 500);
      function cleanup() {
        clearInterval(closePoll);
        window.removeEventListener('message', onMessage);
      }
      function onMessage(e) {
        if (e.origin !== broker || e.data?.type !== 'bq-auth') return;
        cleanup();
        popup.close();
        const who = parseIdToken(e.data.id_token);
        const token = {
          accessToken: e.data.access_token,
          email: who.email,
          name: who.name,
          expiresAt: Date.now() + (e.data.expires_in - 60) * 1000,
        };
        sessionStorage.setItem(CACHE_KEY, JSON.stringify(token));
        resolve(token);
      }
      window.addEventListener('message', onMessage);
    });
  }

  return { getToken, cached, clear };
})();
