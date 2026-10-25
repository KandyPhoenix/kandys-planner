// firebase-signin.js — "sign in to sync" gate shared by Kandy's apps on kandyphoenix.github.io
// (Kandy's Planner, FODMAP app, Wellness Tracker). Identical copy in each repo.
//
// Backward compatible: while the Firestore rules are open the app keeps syncing exactly as
// before and this file does nothing visible. Once the rules are locked to
// kandyphoenix@hotmail.com, Firestore answers "permission-denied", the app calls
// FBSignIn.onError(e), and a bar appears offering a passwordless email-link sign-in.
// Sign in with a password, or with a passwordless email link. One sign-in per device/browser;
// Firebase Auth keeps the session in IndexedDB.
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
  // An installed (home-screen / standalone) copy has the same problem: tapping the emailed link
  // opens the browser, which has its OWN storage, so the sign-in lands there and the installed
  // app never sees it (this is how iOS/iPadOS and Android isolate home-screen web apps). The
  // only way in is to paste the link, so offer the paste row there too.
  var IS_STANDALONE = false;
  try {
    IS_STANDALONE = (global.matchMedia && global.matchMedia('(display-mode: standalone)').matches) ||
                    global.navigator.standalone === true;
  } catch (e) {}
  var NEEDS_PASTE = IS_FILE || IS_STANDALONE;

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
    var btn   = 'margin:0 8px 4px 0;padding:6px 12px;border:0;border-radius:6px;background:#ff1c8d;color:#fff;font-weight:600;cursor:pointer';
    var btn2  = 'margin:0 8px 4px 0;padding:6px 12px;border:1px solid #777;border-radius:6px;background:transparent;color:#fff;cursor:pointer';
    var input = 'padding:6px 8px;margin:0 8px 4px 0;border-radius:6px;border:1px solid #555;background:#111;color:#fff;font-size:16px';
    g.innerHTML = '<button id="fbGateClose" type="button" title="Hide" style="float:right;background:none;border:0;color:#aaa;font-size:16px;cursor:pointer">✕</button>' +
      '🔒 <b>Cloud sync needs you to sign in</b> as ' + ALLOWED + '. <span id="fbGateMsg"></span>' +
      // Password sign-in: works the same in a browser, an installed (home-screen) app and the
      // desktop build, with no emailed link to copy. "Set or reset password" emails a reset link
      // that can be opened anywhere (tapping it is fine); the password is then typed in here.
      '<div style="margin-top:8px">' +
        '<input id="fbGatePw" type="password" placeholder="Password" autocomplete="current-password" style="' + input + 'width:min(60%,260px)">' +
        '<button id="fbGatePwBtn" type="button" style="' + btn + '">Sign in</button>' +
        '<button id="fbGatePwReset" type="button" style="' + btn2 + '">Set or reset password</button>' +
      '</div>' +
      // Emailed sign-in link, kept as the fallback.
      '<div style="margin-top:6px;color:#bbb">Or, instead of a password: ' +
        '<button id="fbGateBtn" type="button" style="' + btn2 + '">Email me a sign-in link</button>' +
        (NEEDS_PASTE ? '<span id="fbGatePasteRow">then copy the link from that email (press and hold it, then Copy — do not tap it) and paste it here: ' +
                   '<input id="fbGateLink" type="url" placeholder="https://kandyphoenix.github.io/..." style="' + input + 'width:min(60%,520px)">' +
                   '<button id="fbGatePasteBtn" type="button" style="' + btn2 + '">Sign in with link</button></span>' : '') +
      '</div>';
    document.body.appendChild(g);
    el('fbGatePwBtn').onclick = signInWithPassword;
    el('fbGatePw').onkeydown = function (ev) { if (ev.key === 'Enter') signInWithPassword(); };
    el('fbGatePwReset').onclick = sendPasswordReset;
    el('fbGateBtn').onclick = sendLink;
    if (el('fbGatePasteBtn')) el('fbGatePasteBtn').onclick = signInWithPastedLink;
    el('fbGateClose').onclick = function () { g.style.display = 'none'; };
    return g;
  }
  function msg(t) { if (el('fbGateMsg')) el('fbGateMsg').textContent = t; }

  // Where emailed links should land afterwards (the app's own web URL).
  function appUrl() { return IS_FILE ? WEB_URL : location.href.split(/[?#]/)[0]; }

  function signInWithPassword() {
    var a = auth(), pw = el('fbGatePw') ? el('fbGatePw').value : '';
    if (!a) { show('Firebase Auth SDK is not loaded on this page.'); return; }
    if (!pw) { msg('Type your password first (or tap "Set or reset password").'); return; }
    msg('Signing in…');
    a.signInWithEmailAndPassword(ALLOWED, pw)
      .then(function () { hide(); location.reload(); })
      .catch(function (e) {
        var c = e.code || '';
        msg(/wrong-password|invalid-login-credentials|invalid-credential|user-not-found/.test(c)
              ? 'Wrong or missing password. Tap "Set or reset password" to make a new one.'
            : c === 'auth/too-many-requests' ? 'Too many tries — wait a few minutes and try again.'
            : c === 'auth/operation-not-allowed' ? 'Password sign-in is not enabled: Firebase console → Authentication → Sign-in method → Email/Password → Enable.'
            : c === 'auth/network-request-failed' ? 'No connection — check the internet and try again.'
            : 'Sign-in failed: ' + (c || e.message));
      });
  }

  function sendPasswordReset() {
    var a = auth();
    if (!a) { show('Firebase Auth SDK is not loaded on this page.'); return; }
    var b = el('fbGatePwReset'); b.disabled = true; b.textContent = 'Sending…';
    a.sendPasswordResetEmail(ALLOWED, { url: appUrl() })
      .then(function () {
        b.textContent = 'Reset email sent';
        msg('Sent to ' + ALLOWED + '. Open that email anywhere and tap its link (that one is fine to tap), choose a password, then come back here and sign in with it. Check spam if it does not arrive.');
      })
      .catch(function (e) {
        b.disabled = false; b.textContent = 'Set or reset password';
        msg('Could not send the reset email: ' + (e.code || e.message));
      });
  }
  function show(msg) { var g = gate(); g.style.display = 'block'; if (msg && el('fbGateMsg')) el('fbGateMsg').textContent = msg; }
  function hide() { var g = el('fbGate'); if (g) g.style.display = 'none'; }

  function sendLink() {
    var a = auth();
    if (!a) { show('Firebase Auth SDK is not loaded on this page.'); return; }
    var b = el('fbGateBtn');
    b.disabled = true; b.textContent = 'Sending…';
    a.sendSignInLinkToEmail(ALLOWED, { url: appUrl(), handleCodeInApp: true })
      .then(function () {
        try { localStorage.setItem(EMAIL_KEY, ALLOWED); } catch (e) {}
        el('fbGateMsg').textContent = IS_FILE
          ? 'Sent to ' + ALLOWED + '. It expires shortly.'
          : IS_STANDALONE
          ? 'Sent to ' + ALLOWED + '. Tapping the link opens the browser, not this app — copy the link and paste it below. It expires shortly.'
          : 'Check ' + ALLOWED + ' and open the link on THIS device. It expires shortly.';
        b.textContent = 'Link sent';
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

  // Desktop or installed build: sign in with a link pasted from the email (the link's one-time
  // code is what matters, not the page it points at).
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
    signInWithPassword: signInWithPassword, sendPasswordReset: sendPasswordReset,
    onError: function (e) { if (denied(e)) { show(); return true; } return false; }
  };
})(window);
