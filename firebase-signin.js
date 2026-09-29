// firebase-signin.js — "sign in to sync" gate shared by Kandy's apps on kandyphoenix.github.io
// (Kandy's Planner, FODMAP app, Wellness Tracker). Identical copy in each repo.
//
// Backward compatible: while the Firestore rules are open the app keeps syncing exactly as
// before and this file does nothing visible. Once the rules are locked to
// kandyphoenix@hotmail.com, Firestore answers "permission-denied", the app calls
// FBSignIn.onError(e), and a bar appears offering a passwordless email-link sign-in.
// One sign-in per device/browser; Firebase Auth keeps the session in IndexedDB.
//
// Requires firebase-app-compat + firebase-auth-compat (9.x) loaded before this file.
(function (global) {
  var ALLOWED   = 'kandyphoenix@hotmail.com';
  var EMAIL_KEY = 'fb_signin_email';
  // A desktop (Electron / file://) build cannot open the emailed link itself, so it asks for the
  // link to be pasted in. The link is still generated against the app's web URL, which must be an
  // authorized domain; the app may set window.FB_SIGNIN_WEB_URL before loading this file.
  var IS_FILE   = location.protocol === 'file:';
  var WEB_URL   = global.FB_SIGNIN_WEB_URL || 'https://kandyphoenix.github.io/';

  function auth() { try { return global.firebase && global.firebase.auth ? global.firebase.auth() : null; } catch (e) { return null; } }
  function el(id) { return document.getElementById(id); }

  // True when Firestore refused the request because of the security rules.
  function denied(e) {
    if (!e) return false;
    var c = String(e.code || ''), m = String(e.message || '');
    return /permission-denied/i.test(c) || /PERMISSION_DENIED|insufficient permissions/i.test(m);
  }

  function gate() {
    var g = el('fbGate');
    if (g) return g;
    g = document.createElement('div');
    g.id = 'fbGate';
    g.setAttribute('style', 'position:fixed;left:0;right:0;top:0;z-index:99999;display:none;padding:10px 14px;' +
      'background:#1a1a2e;color:#fff;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.45)');
    var btn = 'margin:0 8px;padding:6px 12px;border:0;border-radius:6px;background:#ff1c8d;color:#fff;font-weight:600;cursor:pointer';
    g.innerHTML = '\uD83D\uDD12 <b>Cloud sync needs you to sign in</b> as ' + ALLOWED + '. ' +
      '<button id="fbGateBtn" type="button" style="' + btn + '">Email me a sign-in link</button>' +
      '<span id="fbGateMsg"></span>' +
      (IS_FILE ? '<div id="fbGatePasteRow" style="display:none;margin-top:8px">Copy the link from that email (do not tap it) and paste it here: ' +
                 '<input id="fbGateLink" type="url" placeholder="https://kandyphoenix.github.io/..." style="width:min(60%,520px);padding:6px 8px;border-radius:6px;border:1px solid #555;background:#111;color:#fff">' +
                 '<button id="fbGatePasteBtn" type="button" style="' + btn + '">Sign in</button></div>' : '') +
      '<button id="fbGateClose" type="button" title="Hide" style="float:right;background:none;border:0;color:#aaa;font-size:16px;cursor:pointer">\u2715</button>';
    document.body.appendChild(g);
    el('fbGateBtn').onclick = sendLink;
    if (el('fbGatePasteBtn')) el('fbGatePasteBtn').onclick = signInWithPastedLink;
    el('fbGateClose').onclick = function () { g.style.display = 'none'; };
    return g;
  }
  function show(msg) { var g = gate(); g.style.display = 'block'; if (msg && el('fbGateMsg')) el('fbGateMsg').textContent = msg; }
  function hide() { var g = el('fbGate'); if (g) g.style.display = 'none'; }

  function sendLink() {
    var a = auth();
    if (!a) { show('Firebase Auth SDK is not loaded on this page.'); return; }
    var b = el('fbGateBtn');
    b.disabled = true; b.textContent = 'Sending…';
    var url = IS_FILE ? WEB_URL : location.href.split(/[?#]/)[0];
    a.sendSignInLinkToEmail(ALLOWED, { url: url, handleCodeInApp: true })
      .then(function () {
        try { localStorage.setItem(EMAIL_KEY, ALLOWED); } catch (e) {}
        el('fbGateMsg').textContent = IS_FILE
          ? 'Sent to ' + ALLOWED + '. It expires shortly.'
          : 'Check ' + ALLOWED + ' and open the link on THIS device. It expires shortly.';
        b.textContent = 'Link sent';
        if (el('fbGatePasteRow')) el('fbGatePasteRow').style.display = 'block';
      })
      .catch(function (e) {
        b.disabled = false; b.textContent = 'Email me a sign-in link';
        var hint = e.code === 'auth/operation-not-allowed'
          ? ' — Email-link sign-in is not enabled yet: Firebase console → Authentication → Sign-in method → Email/Password → turn on "Email link".'
          : e.code === 'auth/unauthorized-continue-uri'
          ? ' — add kandyphoenix.github.io under Authentication → Settings → Authorized domains.'
          : '';
        el('fbGateMsg').textContent = 'Could not send the link: ' + (e.code || e.message) + hint;
      });
  }

  // Desktop build: sign in with a link pasted from the email (the link's one-time code is what
  // matters, not the page it points at).
  function signInWithPastedLink() {
    var a = auth(), link = (el('fbGateLink').value || '').trim();
    if (!a) { show('Firebase Auth SDK is not loaded on this page.'); return; }
    if (!a.isSignInWithEmailLink(link)) { el('fbGateMsg').textContent = 'That does not look like a sign-in link. Copy the whole link from the email.'; return; }
    el('fbGateMsg').textContent = 'Signing in\u2026';
    a.signInWithEmailLink(ALLOWED, link)
      .then(function () { try { localStorage.removeItem(EMAIL_KEY); } catch (e) {} hide(); location.reload(); })
      .catch(function (e) { el('fbGateMsg').textContent = 'Sign-in failed: ' + (e.code || e.message) + (e.code === 'auth/invalid-action-code' ? ' \u2014 the link was already used or expired; request a new one.' : ''); });
  }

  // Finish the sign-in when the page was opened from the emailed link. Always resolves,
  // so the app can chain its normal sync boot after it.
  function complete() {
    var a = auth();
    try {
      if (a && a.isSignInWithEmailLink(location.href)) {
        var em = null; try { em = localStorage.getItem(EMAIL_KEY); } catch (e) {}
        return a.signInWithEmailLink(em || ALLOWED, location.href)
          .then(function () {
            try { localStorage.removeItem(EMAIL_KEY); } catch (e) {}
            try { history.replaceState({}, '', location.pathname); } catch (e) {}
            hide();
          })
          .catch(function (e) { show('Sign-in link failed: ' + (e.code || e.message) + '. Request a new one.'); });
      }
    } catch (e) {}
    return Promise.resolve();
  }

  function init() { var a = auth(); if (a) a.onAuthStateChanged(function (u) { if (u && u.email === ALLOWED) hide(); }); }

  // Bearer header for direct Firestore REST calls, so they work once the rules are locked.
  function idToken() {
    var a = auth();
    if (!a || !a.currentUser) return Promise.resolve(null);
    return a.currentUser.getIdToken().catch(function () { return null; });
  }

  global.FBSignIn = {
    ALLOWED: ALLOWED, denied: denied, show: show, hide: hide, sendLink: sendLink,
    complete: complete, init: init, idToken: idToken,
    onError: function (e) { if (denied(e)) { show(); return true; } return false; }
  };
})(window);
