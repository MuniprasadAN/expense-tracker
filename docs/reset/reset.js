// Expense Tracker: set a new password from a reset email, in any browser.
//
// The button in the email lands here with a one-time token in the fragment:
//
//   .../reset/#token_hash=<hash>&type=recovery
//
// A fragment is never sent to the server that hosts this page, and nothing
// goes anywhere until the form is submitted. Then, in order:
//
//   1. POST /auth/v1/verify   trades the token for a short-lived session
//   2. PUT  /auth/v1/user     sets the password with that session
//   3. POST /auth/v1/logout   ends every session, this one included
//
// WHY THE TOKEN IS SPENT ON SUBMIT AND NOT ON LOAD. Mail scanners open the
// links they find. A page that verified as it loaded would let one burn the
// token before its owner had read the email, and the owner would meet "this
// link no longer works" on a link nobody had used.
//
// The token is single-use and step 1 spends it, so the SESSION it buys is
// kept in memory (never in storage) for another go when step 2 refuses the
// password. Losing it there would cost the user a whole new email. The token
// itself is copied to sessionStorage until it is spent, so that a phone
// reloading the tab in the background does not lose the link.
(function () {
  'use strict';

  // Both values are public by design. They ship inside the app too, and row
  // level security is what protects the data, not keeping these quiet.
  const SUPABASE_URL = 'https://ngvsjlgjgsrliqnvmzlr.supabase.co';
  const PUBLISHABLE_KEY = 'sb_publishable_CFZJGRthBSgc8ZFJoAd81Q_yJtQ5IV1';

  // The project's password policy, which the app's own form checks too
  // (lib/auth/auth_screens.dart). The server decides; checking here is what
  // lets the page say WHICH rule failed, because the server's refusal is a
  // single weak_password code. Change all three together.
  const MIN_LENGTH = 10;
  // bcrypt, which stores the password, reads 72 bytes and the server refuses
  // anything longer.
  const MAX_BYTES = 72;

  // Long enough for a weak signal, short enough that a stalled request does
  // not leave the button saying "Setting your password..." for minutes.
  const TIMEOUT_MS = 20000;

  const LINK_KEY = 'expense-tracker-reset-link';
  // How the last attempt in this tab ended: 'done' or 'spent'. It holds
  // nothing secret, and it is what a reload shows instead of "open this page
  // from your email" to somebody who has just finished.
  const OUTCOME_KEY = 'expense-tracker-reset-outcome';

  const MESSAGES = {
    offline:
      'Could not reach the server. Check your connection and try again. ' +
      'If it keeps happening on a computer, open the email on your phone instead.',
    slow: 'The server took too long to respond. Try again in a moment.',
    rate: 'Too many attempts. Wait a minute and try again.',
    weak:
      'That password does not meet the requirements: at least 10 characters, ' +
      'with a capital, a lowercase and a digit.',
    same: 'That is already your password. Choose a different one.',
    unknown: 'Something went wrong. Try again in a moment.',
  };

  class ResetError extends Error {
    constructor(reason) {
      super(reason);
      this.name = 'ResetError';
      this.reason = reason;
    }
  }

  /// The token from a reset link, or null when the fragment carries none
  /// worth sending.
  ///
  /// THE FRAGMENT ONLY, NEVER THE QUERY STRING. A query string is sent to the
  /// host in the page request, before any script runs. Accepting one here
  /// would make "?token_hash=" look like a working way to write the email
  /// template, and it would hand every token to the host's logs.
  function readLink(hash) {
    const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
    const tokenHash = params.get('token_hash');
    if (!tokenHash) return null;
    if (!/^[A-Za-z0-9_-]{16,200}$/.test(tokenHash)) return null;
    // A link that says it is something else is not offered the form. That is
    // a courtesy, not the protection: the server looks the token up among
    // recovery tokens only, whatever the address claimed.
    const type = params.get('type');
    if (type && type !== 'recovery') return null;
    return tokenHash;
  }

  function utf8Length(text) {
    let bytes = 0;
    for (const symbol of text) {
      const point = symbol.codePointAt(0);
      bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
    }
    return bytes;
  }

  /// What is wrong with a new password, or null. Everything missing is named
  /// at once, so fixing it is one edit rather than three rounds.
  function passwordProblem(password) {
    if (!password) return 'Enter a new password';
    if (password.length < MIN_LENGTH) {
      return 'Use at least ' + MIN_LENGTH + ' characters';
    }
    const missing = [];
    if (!/[a-z]/.test(password)) missing.push('a lowercase letter');
    if (!/[A-Z]/.test(password)) missing.push('a capital letter');
    if (!/[0-9]/.test(password)) missing.push('a digit');
    if (missing.length === 1) return 'Add ' + missing[0];
    if (missing.length > 1) {
      const last = missing.pop();
      return 'Add ' + missing.join(', ') + ' and ' + last;
    }
    // No number in the message: the limit is in bytes, and a letter outside
    // the Latin alphabet is three of them, so any count would be wrong.
    if (utf8Length(password) > MAX_BYTES) {
      return 'That password is too long. Use a shorter one.';
    }
    return null;
  }

  function confirmProblem(password, confirm) {
    if (!confirm) return 'Type the password again';
    if (confirm !== password) return 'Those passwords do not match';
    return null;
  }

  // The auth server answers in two shapes, depending on the API version it
  // takes the caller to speak: {code: 403, error_code: 'otp_expired', msg}
  // and {code: 'otp_expired', message}. Both are read.
  function errorCode(data) {
    if (!data || typeof data !== 'object') return '';
    if (typeof data.error_code === 'string') return data.error_code;
    if (typeof data.code === 'string') return data.code;
    return '';
  }

  /// What went wrong, as one of the words the page knows how to explain:
  /// link, weak, same, rate or unknown.
  function reasonFor(step, status, data) {
    const code = errorCode(data);
    if (status === 429 || /rate_limit$/.test(code)) return 'rate';
    if (step === 'verify') {
      // Expired, already used, replaced by a newer email, never issued: the
      // server gives all of them this one code, and to the person holding
      // the link they are one thing. It will not work. By the code and not by
      // the 403 it arrives with: other refusals share that status without
      // having spent the token, and must not be reported as a dead link.
      if (code === 'otp_expired') return 'link';
      return 'unknown';
    }
    if (code === 'weak_password') return 'weak';
    if (code === 'same_password') return 'same';
    // The session from step 1 lasts an hour. Once it is gone there is no
    // finishing without a new link, which is the same advice again.
    if (status === 401 || status === 403) return 'link';
    return 'unknown';
  }

  /// A signal that gives up after [TIMEOUT_MS], with the timer to cancel
  /// once the answer is in.
  function deadline() {
    if (typeof AbortController !== 'function') return { signal: undefined, cancel: () => {} };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    return { signal: controller.signal, cancel: () => clearTimeout(timer) };
  }

  async function call(fetchFn, step, method, path, token, body) {
    const headers = { apikey: PUBLISHABLE_KEY, 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    const limit = deadline();
    let response;
    let data = null;
    try {
      response = await fetchFn(SUPABASE_URL + '/auth/v1' + path, {
        method: method,
        headers: headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: limit.signal,
      });
      try {
        data = await response.json();
      } catch (error) {
        // Nothing to read: logout answers 204, and a gateway in trouble
        // answers with a page that is not JSON. A body cut off by the
        // deadline is a slow server, though, and is reported as one.
        if (limit.signal && limit.signal.aborted) throw error;
      }
    } catch (error) {
      throw new ResetError(limit.signal && limit.signal.aborted ? 'slow' : 'offline');
    } finally {
      limit.cancel();
    }
    if (!response.ok) throw new ResetError(reasonFor(step, response.status, data));
    return data;
  }

  /// Runs the three steps. `state` carries the token in and keeps the session
  /// between attempts; a failure is thrown as a ResetError naming the reason.
  async function setPassword(fetchFn, state, password) {
    if (!state.accessToken) {
      // Neither a token nor a session: an earlier attempt spent the one and
      // never got the other. Only a new link can help.
      if (!state.tokenHash) throw new ResetError('link');
      const session = await call(fetchFn, 'verify', 'POST', '/verify', null, {
        type: 'recovery',
        token_hash: state.tokenHash,
      });
      // The token is spent from here on, whatever the answer looked like.
      state.tokenHash = null;
      if (!session || typeof session.access_token !== 'string') {
        throw new ResetError('unknown');
      }
      state.accessToken = session.access_token;
    }

    try {
      await call(fetchFn, 'update', 'PUT', '/user', state.accessToken, {
        password: password,
      });
    } catch (error) {
      const reason = error instanceof ResetError ? error.reason : 'unknown';
      // A LOST ANSWER IS NOT A FAILED UPDATE. When the update commits and its
      // response never arrives (a phone dropping signal), the retry with the
      // same password is refused as same_password - for a reset that worked.
      // So a try that got no answer is remembered, and "same" for that very
      // password is read as the earlier try having landed.
      const landed = reason === 'same' && state.unconfirmed === password;
      const unanswered = reason === 'offline' || reason === 'slow' || reason === 'unknown';
      state.unconfirmed = unanswered ? password : null;
      if (!landed) throw error;
    }
    state.unconfirmed = null;

    const session = state.accessToken;
    state.accessToken = null;
    try {
      // Global, so nothing minted under the old password outlives it - and
      // this page's own session goes with the rest.
      await call(fetchFn, 'logout', 'POST', '/logout?scope=global', session);
    } catch (error) {
      // The password is changed, which is what was asked for. Failing to end
      // the sessions is never worth reporting as a failed reset.
    }
  }

  function isFramed(win) {
    try {
      return win.top !== win.self;
    } catch (error) {
      return true;
    }
  }

  // sessionStorage can be missing or refuse (private windows, blocked site
  // data), and none of that may stop the page: the token is also in memory.
  function tabStore(win) {
    let store = null;
    try {
      store = win.sessionStorage;
    } catch (error) {
      store = null;
    }
    const attempt = (action) => {
      try {
        return store ? action(store) : null;
      } catch (error) {
        return null;
      }
    };
    return {
      get: (key) => attempt((s) => s.getItem(key)),
      set: (key, value) => attempt((s) => s.setItem(key, value)),
      remove: (key) => attempt((s) => s.removeItem(key)),
    };
  }

  function start(win) {
    const doc = win.document;
    const byId = (id) => doc.getElementById(id);
    const views = ['view-form', 'view-done', 'view-invalid', 'view-missing', 'view-framed'];

    function show(id, moveFocus) {
      const loading = byId('loading');
      if (loading) loading.hidden = true;
      for (const view of views) byId(view).hidden = view !== id;
      const heading = byId(id).querySelector('h1');
      // The tab and the task switcher show the title, and "Set a new
      // password" over "Password changed" reads as unfinished.
      doc.title = heading.textContent + ' - Expense Tracker';
      // A changed view is announced by moving to its heading. Not on the
      // first one: the page has only just opened and nothing has changed.
      if (moveFocus) heading.focus();
    }

    // A page that can be framed can be dressed up as something else. Checked
    // before the token is read, so a framed copy never stores or sends it.
    if (isFramed(win)) {
      show('view-framed', false);
      return;
    }

    const store = tabStore(win);
    let tokenHash = readLink(win.location.hash);
    if (tokenHash) {
      store.set(LINK_KEY, tokenHash);
      store.remove(OUTCOME_KEY);
      // Out of the address bar, so the token is not copied along with the
      // address, bookmarked or caught in a screenshot. (A browser may still
      // keep the original address in its history.)
      try {
        win.history.replaceState(null, '', win.location.pathname);
      } catch (error) {
        // Cosmetic. The reset works the same with the address left as it is.
      }
    } else {
      // A reload, usually a phone bringing a background tab back. Say how
      // the attempt ended rather than "open this page from your email" - to
      // somebody who has just finished, that reads as the reset not having
      // happened.
      const outcome = store.get(OUTCOME_KEY);
      if (outcome === 'done') {
        show('view-done', false);
        return;
      }
      if (outcome === 'spent') {
        show('view-invalid', false);
        return;
      }
      tokenHash = readLink('token_hash=' + (store.get(LINK_KEY) || ''));
    }
    if (!tokenHash) {
      show('view-missing', false);
      return;
    }

    const form = byId('reset-form');
    const password = byId('password');
    const confirm = byId('confirm');
    const toggle = byId('toggle');
    const submit = byId('submit');
    const passwordError = byId('password-error');
    const confirmError = byId('confirm-error');
    const banner = byId('form-error');

    const state = { tokenHash: tokenHash, accessToken: null, unconfirmed: null };
    let busy = false;
    // Errors appear at the first submit and then follow the typing, as the
    // app's own form does. "Use at least 10 characters" under a password that
    // is one letter in is nagging, not help.
    let checked = false;
    // What the server said about the password, kept until the password changes.
    let refused = null;

    function mark(input, target, message) {
      const text = message || '';
      // Only when it changes: these are live regions, and rewriting the same
      // words on every keystroke has a screen reader repeat them per key.
      if (target.textContent !== text) target.textContent = text;
      if (text) {
        input.setAttribute('aria-invalid', 'true');
      } else {
        input.removeAttribute('aria-invalid');
      }
    }

    /// Shows what is wrong and returns the first field that needs fixing.
    function validate() {
      const first = refused || passwordProblem(password.value);
      const second = confirmProblem(password.value, confirm.value);
      mark(password, passwordError, first);
      mark(confirm, confirmError, second);
      if (first) return password;
      return second ? confirm : null;
    }

    function setBusy(value) {
      busy = value;
      // aria-disabled, not disabled: a disabled button drops the focus it
      // was holding, and a screen reader loses its place mid-submit.
      submit.setAttribute('aria-disabled', value ? 'true' : 'false');
      submit.textContent = value ? 'Setting your password…' : 'Set new password';
    }

    function clearFields() {
      password.value = '';
      confirm.value = '';
    }

    password.addEventListener('input', () => {
      refused = null;
      if (checked) validate();
    });
    confirm.addEventListener('input', () => {
      if (checked) validate();
    });

    toggle.addEventListener('click', () => {
      const reveal = password.type === 'password';
      password.type = reveal ? 'text' : 'password';
      confirm.type = password.type;
      toggle.textContent = reveal ? 'Hide' : 'Show';
      toggle.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (busy) return;
      checked = true;
      // Before the check, so an old "could not reach the server" does not sit
      // beside a field error for a submit that sent nothing.
      banner.textContent = '';
      const invalid = validate();
      if (invalid) {
        invalid.focus();
        return;
      }

      setBusy(true);
      let outcome = null;
      try {
        await setPassword(win.fetch.bind(win), state, password.value);
        outcome = 'done';
        clearFields();
        show('view-done', true);
      } catch (error) {
        const reason = error instanceof ResetError ? error.reason : 'unknown';
        if (reason === 'link') {
          // Dead either way, so neither is kept for the next submit.
          state.tokenHash = null;
          state.accessToken = null;
          clearFields();
          show('view-invalid', true);
        } else if (reason === 'weak' || reason === 'same') {
          refused = MESSAGES[reason];
          validate();
          password.focus();
        } else {
          banner.textContent = MESSAGES[reason] || MESSAGES.unknown;
        }
      } finally {
        // A spent token is no use to a reload, so it does not stay behind.
        // What a reload shows instead is how this attempt ended.
        if (!state.tokenHash) {
          store.remove(LINK_KEY);
          store.set(OUTCOME_KEY, outcome || 'spent');
        }
        setBusy(false);
      }
    });

    show('view-form', false);
  }

  const api = {
    MESSAGES: MESSAGES,
    ResetError: ResetError,
    confirmProblem: confirmProblem,
    isFramed: isFramed,
    passwordProblem: passwordProblem,
    readLink: readLink,
    reasonFor: reasonFor,
    setPassword: setPassword,
    start: start,
  };

  // The tests load this file as a module and call the pieces; a browser has
  // no `module`, and there the page simply starts.
  if (typeof module === 'object' && module && module.exports) {
    module.exports = api;
  } else {
    start(window);
  }
})();
