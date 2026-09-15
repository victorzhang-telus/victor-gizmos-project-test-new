// BQAuthGate — drop-in login page for Gizmos portals using the bq-auth broker.
// Include AFTER bq-auth-client.js and BEFORE the app's own scripts:
//   <script src="bq-auth-client.js"></script>
//   <script src="auth-gate.js"></script>
//
// It hides the app behind a full-page "Sign in to Use" view until the user
// signs in with Google, then reveals the app. App code waits for the token:
//   const token = await BQAuthGate.ready();
//   // token.accessToken, token.email, token.name, token.expiresAt
// On a 401 (token expired): const fresh = await BQAuthGate.reauth();
// To sign out: BQAuthGate.signOut();

const BQAuthGate = (() => {
  const STYLE = `
    #bq-auth-gate {
      position: fixed; inset: 0; z-index: 99999;
      display: flex; align-items: center; justify-content: center;
      background: #f6f7f9;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }
    #bq-auth-gate .bq-card {
      max-width: 26rem; margin: 1rem; padding: 2rem; text-align: center;
      background: #fff; border: 1px solid #e5e7eb; border-radius: 0.75rem;
      color: #1a1a1e;
    }
    #bq-auth-gate h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
    #bq-auth-gate p { color: #6b7280; font-size: 0.875rem; line-height: 1.5; margin: 0; }
    #bq-auth-gate button {
      font: inherit; font-weight: 600; cursor: pointer; margin-top: 1rem;
      padding: 0.55rem 1.1rem; border-radius: 0.5rem; border: none;
      background: #2b6cf6; color: #fff;
    }
    #bq-auth-gate button:hover { filter: brightness(1.08); }
    #bq-auth-gate .bq-error { color: #b91c1c; margin-top: 0.75rem; }
    #bq-auth-gate .bq-error:empty { display: none; }
    @media (prefers-color-scheme: dark) {
      #bq-auth-gate { background: #111318; }
      #bq-auth-gate .bq-card { background: #1b1e26; border-color: #2a2e39; color: #e7e9ee; }
      #bq-auth-gate p { color: #9aa1ad; }
      #bq-auth-gate .bq-error { color: #f87171; }
    }
  `;

  let token = null;
  let resolveReady;
  let readyPromise = new Promise((r) => { resolveReady = r; });

  function buildGate() {
    const style = document.createElement('style');
    style.textContent = STYLE;
    document.head.appendChild(style);

    const gate = document.createElement('div');
    gate.id = 'bq-auth-gate';
    const card = document.createElement('div');
    card.className = 'bq-card';
    const h1 = document.createElement('h1');
    h1.textContent = 'Sign in to Use';
    const line = document.createElement('p');
    line.textContent = "Your Google account's own permissions decide what you can see. Nothing is stored.";
    const btn = document.createElement('button');
    btn.textContent = 'Sign in with Google';
    const err = document.createElement('p');
    err.className = 'bq-error';
    btn.onclick = async () => {
      err.textContent = '';
      try {
        token = await BQAuth.getToken();
        gate.remove();
        resolveReady(token);
        document.dispatchEvent(new CustomEvent('bq-auth-ready', { detail: token }));
      } catch (e) {
        err.textContent = e.message;
      }
    };
    card.append(h1, line, btn, err);
    gate.appendChild(card);
    document.body.appendChild(gate);
  }

  function init() {
    token = BQAuth.cached();
    if (token) {
      resolveReady(token);
      document.dispatchEvent(new CustomEvent('bq-auth-ready', { detail: token }));
    } else {
      buildGate();
    }
  }

  function reauth() {
    BQAuth.clear();
    token = null;
    readyPromise = new Promise((r) => { resolveReady = r; });
    buildGate();
    return readyPromise;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    ready: () => readyPromise,
    token: () => token,
    reauth,
    signOut: () => { BQAuth.clear(); location.reload(); },
  };
})();
