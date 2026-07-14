/*
 * Passwordless passkey sign-in for the hosted login page. Runs the WebAuthn get() ceremony:
 * fetch a server challenge, ask the authenticator to sign it, POST the assertion back. The server
 * (via mfa-webauthn-service) verifies the signature/challenge/origin and resolves the user. Served as
 * an external same-origin file so it satisfies the login page's strict CSP (no inline script).
 */
(function () {
  var btn = document.getElementById('passkey-btn');
  var errEl = document.getElementById('passkey-error');
  if (!btn) return;
  // Hide the option in browsers without WebAuthn rather than offer something that can't work.
  if (!window.PublicKeyCredential) { btn.style.display = 'none'; return; }

  function b64urlToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    var pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
    var bin = atob(s + pad);
    var buf = new ArrayBuffer(bin.length);
    var view = new Uint8Array(buf);
    for (var i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
    return buf;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function signIn() {
    if (errEl) errEl.style.display = 'none';
    btn.disabled = true;
    try {
      var tenantEl = document.getElementById('tenant');
      var tenant = tenantEl ? tenantEl.value : '';
      var optRes = await fetch('/login/webauthn/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant: tenant })
      });
      if (!optRes.ok) throw new Error('options');
      var opt = await optRes.json();

      var publicKey = {
        challenge: b64urlToBuf(opt.challenge),
        rpId: opt.rpId,
        timeout: opt.timeout,
        userVerification: opt.userVerification || 'preferred',
        allowCredentials: (opt.allowCredentials || []).map(function (c) {
          return { type: 'public-key', id: b64urlToBuf(c.id) };
        })
      };
      var cred = await navigator.credentials.get({ publicKey: publicKey });
      if (!cred) throw new Error('cancelled');

      var r = cred.response;
      var assertion = {
        challengeId: opt.challengeId,
        credentialId: cred.id,
        authenticatorData: bufToB64url(r.authenticatorData),
        clientDataJSON: bufToB64url(r.clientDataJSON),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null
      };
      var verRes = await fetch('/login/webauthn/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertion)
      });
      if (!verRes.ok) throw new Error('verify');
      var out = await verRes.json();
      window.location.assign(out.redirect || '/');
    } catch (e) {
      if (errEl) errEl.style.display = 'block';
      btn.disabled = false;
    }
  }

  btn.addEventListener('click', signIn);
})();
