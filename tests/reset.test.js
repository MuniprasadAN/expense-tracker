'use strict';

// Two layers. The first calls the page's own functions with a fake server, so
// the three requests and every refusal are pinned without a browser. The
// second loads the real HTML into jsdom and drives the form, because a page
// whose logic is right can still show the wrong view.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const page = require('../docs/reset/reset.js');

const html = fs.readFileSync(path.join(__dirname, '../docs/reset/index.html'), 'utf8');
const source = fs.readFileSync(path.join(__dirname, '../docs/reset/reset.js'), 'utf8');

const BASE = 'https://ngvsjlgjgsrliqnvmzlr.supabase.co/auth/v1';
const PAGE = 'https://muniprasadan.github.io/expense-tracker/reset/';
// What the app's own requests produce: the hash of the token, behind the
// prefix the auth server gives a PKCE flow.
const HASH = 'pkce_' + 'a1b2c3d4'.repeat(7);
const GOOD = 'Correct-Horse-9';
const SESSION = { access_token: 'session-jwt', token_type: 'bearer', user: { id: 'u1' } };

const ok = (body) => ({ status: 200, body });
const refused = (status, body) => ({ status, body });
const EXPIRED = refused(403, {
  code: 403,
  error_code: 'otp_expired',
  msg: 'Email link is invalid or has expired',
});

/// A stand-in for the auth server: replies are queued per path and every
/// request is recorded. A reply of 'hang' never answers, and gives up only
/// when the caller's own deadline aborts it.
function server(replies) {
  const calls = [];
  const queues = {};
  for (const [route, list] of Object.entries(replies)) queues[route] = list.slice();
  const fetch = async (url, init) => {
    const route = url.slice(BASE.length).split('?')[0];
    calls.push({
      url,
      route,
      method: init.method,
      headers: init.headers,
      body: init.body === undefined ? undefined : JSON.parse(init.body),
    });
    const reply = (queues[route] || []).shift();
    if (reply === undefined) throw new Error('unexpected request to ' + route);
    if (reply instanceof Error) throw reply;
    if (reply === 'hang') {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const error = new Error('The operation was aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    }
    return {
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      json: async () => {
        if (reply.body === undefined) throw new SyntaxError('no body');
        return reply.body;
      },
    };
  };
  return { fetch, calls };
}

const routes = (calls) => calls.map((call) => call.method + ' ' + call.route);

async function reasonOf(promise) {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof page.ResetError, 'threw something other than a ResetError: ' + error);
    return error.reason;
  }
  return null;
}

// --- the link ----------------------------------------------------------------

test('the token is read from the fragment', () => {
  assert.equal(page.readLink('#token_hash=' + HASH + '&type=recovery'), HASH);
});

test('a link with no type is taken as a reset', () => {
  assert.equal(page.readLink('#token_hash=' + HASH), HASH);
});

test('a link labelled as another type is not offered the form', () => {
  assert.equal(page.readLink('#token_hash=' + HASH + '&type=signup'), null);
  assert.equal(page.readLink('#token_hash=' + HASH + '&type=invite'), null);
});

test('something that is not a token is not sent anywhere', () => {
  assert.equal(page.readLink('#token_hash=<script>alert(1)</script>'), null);
  assert.equal(page.readLink('#token_hash=short'), null);
  assert.equal(page.readLink('#token_hash=' + 'a'.repeat(201)), null);
  assert.equal(page.readLink(''), null);
  assert.equal(page.readLink('#access_token=abc'), null);
});

// --- the password rules ------------------------------------------------------

test('the password rules are the app\'s, and everything missing is named at once', () => {
  assert.equal(page.passwordProblem(''), 'Enter a new password');
  assert.equal(page.passwordProblem('Short1'), 'Use at least 10 characters');
  assert.equal(page.passwordProblem('alllowercase1'), 'Add a capital letter');
  assert.equal(page.passwordProblem('ALLUPPERCASE1'), 'Add a lowercase letter');
  assert.equal(page.passwordProblem('NoDigitsHere'), 'Add a digit');
  assert.equal(page.passwordProblem('alllowercase'), 'Add a capital letter and a digit');
  assert.equal(
    page.passwordProblem('1234567890'),
    'Add a lowercase letter and a capital letter',
  );
  assert.equal(
    page.passwordProblem('----------'),
    'Add a lowercase letter, a capital letter and a digit',
  );
  assert.equal(page.passwordProblem(GOOD), null);
});

test('a password the server would refuse for length is refused here first', () => {
  assert.equal(page.passwordProblem('Aa1' + 'x'.repeat(69)), null);
  assert.match(page.passwordProblem('Aa1' + 'x'.repeat(70)), /too long/);
  // The limit is 72 BYTES, and each of these letters is three of them: 27
  // characters on screen, 75 on the wire.
  const mixed = 'Aa1' + String.fromCodePoint(0x0905).repeat(24);
  assert.equal(mixed.length, 27);
  assert.match(page.passwordProblem(mixed), /too long/);
  // So the message must not quote a number of characters.
  assert.doesNotMatch(page.passwordProblem(mixed), /[0-9]/);
});

test('the second box catches a typo', () => {
  assert.equal(page.confirmProblem(GOOD, ''), 'Type the password again');
  assert.equal(page.confirmProblem(GOOD, GOOD + 'x'), 'Those passwords do not match');
  assert.equal(page.confirmProblem(GOOD, GOOD), null);
});

// --- the three requests ------------------------------------------------------

test('a reset is verify, then the password, then sign out everywhere', async () => {
  const { fetch, calls } = server({
    '/verify': [ok(SESSION)],
    '/user': [ok({ id: 'u1' })],
    '/logout': [refused(204)],
  });
  const state = { tokenHash: HASH, accessToken: null };
  await page.setPassword(fetch, state, GOOD);

  assert.deepEqual(routes(calls), ['POST /verify', 'PUT /user', 'POST /logout']);
  assert.deepEqual(calls[0].body, { type: 'recovery', token_hash: HASH });
  assert.equal(calls[0].headers.Authorization, undefined);
  assert.deepEqual(calls[1].body, { password: GOOD });
  assert.equal(calls[1].headers.Authorization, 'Bearer session-jwt');
  assert.equal(calls[2].url, BASE + '/logout?scope=global');
  assert.equal(calls[2].headers.Authorization, 'Bearer session-jwt');
  for (const call of calls) {
    assert.match(call.headers.apikey, /^sb_publishable_/);
  }
  assert.deepEqual(state, { tokenHash: null, accessToken: null, unconfirmed: null });
});

test('an update whose answer was lost is not reported as "already your password"', async () => {
  // The update commits, the response is dropped, the user presses again. The
  // server now compares the password with the one it just stored and refuses
  // it as the same - for a reset that worked.
  const { fetch, calls } = server({
    '/verify': [ok(SESSION)],
    '/user': [
      new TypeError('Failed to fetch'),
      refused(422, { code: 422, error_code: 'same_password', msg: 'should be different' }),
    ],
    '/logout': [refused(204)],
  });
  const state = { tokenHash: HASH, accessToken: null, unconfirmed: null };
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'offline');
  await page.setPassword(fetch, state, GOOD);
  assert.deepEqual(routes(calls), ['POST /verify', 'PUT /user', 'PUT /user', 'POST /logout']);
});

test('but a different password on the retry is still told it is the current one', async () => {
  const { fetch } = server({
    '/verify': [ok(SESSION)],
    '/user': [
      new TypeError('Failed to fetch'),
      refused(422, { code: 422, error_code: 'same_password', msg: 'should be different' }),
    ],
  });
  const state = { tokenHash: HASH, accessToken: null, unconfirmed: null };
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'offline');
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD + '!')), 'same');
});

test('a refusal that did not spend the token is not called a dead link', () => {
  // A banned account is refused with the same 403 as an expired link, but
  // the token is untouched and a new email would be refused the same way.
  assert.equal(
    page.reasonFor('verify', 403, { code: 403, error_code: 'user_banned', msg: 'User is banned' }),
    'unknown',
  );
  assert.equal(page.reasonFor('verify', 403, null), 'unknown');
});

test('no request carries the token or the password in its address', async () => {
  const { fetch, calls } = server({
    '/verify': [ok(SESSION)],
    '/user': [ok({})],
    '/logout': [refused(204)],
  });
  await page.setPassword(fetch, { tokenHash: HASH, accessToken: null }, GOOD);
  for (const call of calls) {
    assert.ok(!call.url.includes(HASH), call.url);
    assert.ok(!call.url.includes(GOOD), call.url);
  }
});

test('an expired or used link is reported as the link, and nothing else is sent', async () => {
  const { fetch, calls } = server({ '/verify': [EXPIRED] });
  const reason = await reasonOf(
    page.setPassword(fetch, { tokenHash: HASH, accessToken: null }, GOOD),
  );
  assert.equal(reason, 'link');
  assert.deepEqual(routes(calls), ['POST /verify']);
});

test('the newer error shape is read too', () => {
  assert.equal(
    page.reasonFor('verify', 403, { code: 'otp_expired', message: 'Email link is invalid' }),
    'link',
  );
  assert.equal(page.reasonFor('update', 422, { code: 'weak_password', message: 'weak' }), 'weak');
});

test('a refused password keeps the session, so the retry needs no new email', async () => {
  const { fetch, calls } = server({
    '/verify': [ok(SESSION)],
    '/user': [
      refused(422, { code: 422, error_code: 'same_password', msg: 'should be different' }),
      refused(422, { code: 422, error_code: 'weak_password', msg: 'weak' }),
      ok({}),
    ],
    '/logout': [refused(204)],
  });
  const state = { tokenHash: HASH, accessToken: null };

  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'same');
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'weak');
  await page.setPassword(fetch, state, GOOD + '!');

  // One verify for three attempts: the token was spent by the first.
  assert.deepEqual(routes(calls), [
    'POST /verify',
    'PUT /user',
    'PUT /user',
    'PUT /user',
    'POST /logout',
  ]);
});

test('no connection is not a dead link: the token is kept for the retry', async () => {
  const { fetch, calls } = server({
    '/verify': [new TypeError('Failed to fetch'), ok(SESSION)],
    '/user': [ok({})],
    '/logout': [refused(204)],
  });
  const state = { tokenHash: HASH, accessToken: null };
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'offline');
  assert.equal(state.tokenHash, HASH);
  await page.setPassword(fetch, state, GOOD);
  assert.equal(calls.length, 4);
});

test('a server that never answers is given up on, and said to be slow', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { fetch } = server({ '/verify': ['hang'] });
  const state = { tokenHash: HASH, accessToken: null };
  const attempt = reasonOf(page.setPassword(fetch, state, GOOD));
  // Let the request go out, then run the clock past the page's deadline.
  await Promise.resolve();
  t.mock.timers.tick(20000);
  assert.equal(await attempt, 'slow');
  // Whether the server saw it is unknown, so the token is kept for a retry.
  assert.equal(state.tokenHash, HASH);
});

test('too many attempts says so, at either step', async () => {
  const limited = refused(429, { code: 429, error_code: 'over_request_rate_limit', msg: 'slow down' });
  const first = server({ '/verify': [limited] });
  assert.equal(
    await reasonOf(page.setPassword(first.fetch, { tokenHash: HASH, accessToken: null }, GOOD)),
    'rate',
  );
  const second = server({ '/verify': [ok(SESSION)], '/user': [limited] });
  assert.equal(
    await reasonOf(page.setPassword(second.fetch, { tokenHash: HASH, accessToken: null }, GOOD)),
    'rate',
  );
});

test('a session that ran out before the password was set needs a new link', async () => {
  const { fetch } = server({
    '/verify': [ok(SESSION)],
    '/user': [refused(401, { code: 401, error_code: 'bad_jwt', msg: 'invalid JWT' })],
  });
  assert.equal(
    await reasonOf(page.setPassword(fetch, { tokenHash: HASH, accessToken: null }, GOOD)),
    'link',
  );
});

test('a server in trouble is not blamed on the link', async () => {
  const { fetch } = server({ '/verify': [refused(502, undefined)] });
  const state = { tokenHash: HASH, accessToken: null };
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'unknown');
  assert.equal(state.tokenHash, HASH);
});

test('an answer with no session spends the token and is not retried with it', async () => {
  const { fetch, calls } = server({ '/verify': [ok({})] });
  const state = { tokenHash: HASH, accessToken: null };
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'unknown');
  assert.equal(await reasonOf(page.setPassword(fetch, state, GOOD)), 'link');
  assert.equal(calls.length, 1);
});

test('a failed sign-out does not turn a changed password into a failure', async () => {
  const { fetch, calls } = server({
    '/verify': [ok(SESSION)],
    '/user': [ok({})],
    '/logout': [new TypeError('Failed to fetch')],
  });
  await page.setPassword(fetch, { tokenHash: HASH, accessToken: null }, GOOD);
  assert.equal(calls.length, 3);
});

test('a page inside a frame knows it', () => {
  const alone = {};
  alone.top = alone;
  alone.self = alone;
  assert.equal(page.isFramed(alone), false);
  assert.equal(page.isFramed({ top: {}, self: {} }), true);
  const crossOrigin = {
    get top() {
      throw new Error('blocked');
    },
    self: {},
  };
  assert.equal(page.isFramed(crossOrigin), true);
});

// --- the page itself ---------------------------------------------------------

const LINK = PAGE + '#token_hash=' + HASH + '&type=recovery';
const LINK_KEY = 'expense-tracker-reset-link';
const OUTCOME_KEY = 'expense-tracker-reset-outcome';

/// The real HTML with the real script, opened at [address]. The script tag in
/// the page is not followed; the source is evaluated in the window instead,
/// after the fake server is in place.
function open(address, replies, prepare) {
  const dom = new JSDOM(html, { url: address, runScripts: 'outside-only' });
  const fake = server(replies || {});
  dom.window.fetch = fake.fetch;
  if (prepare) prepare(dom.window);
  dom.window.eval(source);
  const doc = dom.window.document;
  return {
    window: dom.window,
    doc,
    calls: fake.calls,
    byId: (id) => doc.getElementById(id),
    stored: (key) => dom.window.sessionStorage.getItem(key),
    visible: () =>
      Array.from(doc.querySelectorAll('section'))
        .filter((section) => !section.hidden)
        .map((section) => section.id),
    type(id, value) {
      const input = doc.getElementById(id);
      input.value = value;
      input.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    },
    press() {
      doc
        .getElementById('reset-form')
        .dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
    },
    async submit() {
      this.press();
      // The handler is async; let its requests and the view change settle.
      for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve));
    },
  };
}

test('opened from the email: the form shows and the token leaves the address bar', () => {
  const view = open(LINK);
  assert.deepEqual(view.visible(), ['view-form']);
  assert.equal(view.window.location.href, PAGE);
  assert.equal(view.stored(LINK_KEY), HASH);
  assert.equal(view.byId('loading').hidden, true);
  assert.equal(view.doc.title, 'Set a new password - Expense Tracker');
  assert.equal(view.calls.length, 0, 'nothing may be sent before the form is submitted');
});

test('opened with no link: it says where the link comes from', () => {
  const view = open(PAGE);
  assert.deepEqual(view.visible(), ['view-missing']);
  assert.equal(view.byId('loading').hidden, true);
  assert.equal(view.doc.title, 'Open this page from your reset email - Expense Tracker');
});

test('a token in the query string is not accepted', () => {
  // That form reaches the host in the page request. Refusing it keeps
  // "?token_hash=" from ever looking like a working email template.
  const view = open(PAGE + '?token_hash=' + HASH + '&type=recovery');
  assert.deepEqual(view.visible(), ['view-missing']);
  assert.equal(view.stored(LINK_KEY), null);
});

test('a reload of the same tab still has the link', () => {
  const view = open(PAGE, {}, (window) => window.sessionStorage.setItem(LINK_KEY, HASH));
  assert.deepEqual(view.visible(), ['view-form']);
});

test('junk left in storage is not treated as a link', () => {
  const view = open(PAGE, {}, (window) => window.sessionStorage.setItem(LINK_KEY, '<b>nope</b>'));
  assert.deepEqual(view.visible(), ['view-missing']);
});

test('inside a frame the form never appears and the token is neither kept nor sent', () => {
  // jsdom cannot frame a page at a real address, so the page's own start() is
  // handed a window that says it is framed, over a real document.
  const dom = new JSDOM(html, { url: LINK, runScripts: 'outside-only' });
  const calls = [];
  page.start({
    document: dom.window.document,
    location: dom.window.location,
    history: dom.window.history,
    sessionStorage: dom.window.sessionStorage,
    fetch: async (url) => calls.push(url),
    top: {},
    self: {},
  });
  const shown = Array.from(dom.window.document.querySelectorAll('section'))
    .filter((section) => !section.hidden)
    .map((section) => section.id);
  assert.deepEqual(shown, ['view-framed']);
  assert.equal(dom.window.sessionStorage.getItem(LINK_KEY), null);
  assert.equal(calls.length, 0);
});

test('a password that breaks the rules is stopped on the page', async () => {
  const view = open(LINK);
  view.type('password', 'short');
  view.type('confirm', 'short');
  await view.submit();

  assert.equal(view.byId('password-error').textContent, 'Use at least 10 characters');
  assert.equal(view.byId('password').getAttribute('aria-invalid'), 'true');
  assert.equal(view.doc.activeElement, view.byId('password'));
  assert.equal(view.calls.length, 0);

  // Once flagged, the error follows the typing instead of waiting for submit.
  view.type('password', GOOD);
  assert.equal(view.byId('password-error').textContent, '');
  assert.equal(view.byId('password').hasAttribute('aria-invalid'), false);
  assert.equal(view.byId('confirm-error').textContent, 'Those passwords do not match');
});

test('nothing is flagged before the first submit', () => {
  const view = open(LINK);
  view.type('password', 'a');
  assert.equal(view.byId('password-error').textContent, '');
});

test('an error that has not changed is not written again on every keystroke', async () => {
  // The error elements are live regions: rewriting the same words makes a
  // screen reader repeat them for each key pressed.
  const view = open(LINK);
  view.type('password', 'ab');
  view.type('confirm', 'ab');
  await view.submit();
  assert.equal(view.byId('password-error').textContent, 'Use at least 10 characters');

  let writes = 0;
  const observer = new view.window.MutationObserver((records) => {
    writes += records.length;
  });
  observer.observe(view.byId('password-error'), { childList: true, characterData: true, subtree: true });
  view.type('password', 'abc');
  view.type('password', 'abcd');
  await new Promise((resolve) => setImmediate(resolve));
  observer.disconnect();
  assert.equal(writes, 0);
});

test('two different passwords are stopped on the page', async () => {
  const view = open(LINK);
  view.type('password', GOOD);
  view.type('confirm', GOOD + 'x');
  await view.submit();
  assert.equal(view.byId('confirm-error').textContent, 'Those passwords do not match');
  assert.equal(view.doc.activeElement, view.byId('confirm'));
  assert.equal(view.calls.length, 0);
});

test('a good password goes through and the page says what to do next', async () => {
  const view = open(LINK, {
    '/verify': [ok(SESSION)],
    '/user': [ok({})],
    '/logout': [refused(204)],
  });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  await view.submit();

  assert.deepEqual(view.visible(), ['view-done']);
  assert.deepEqual(routes(view.calls), ['POST /verify', 'PUT /user', 'POST /logout']);
  assert.equal(view.byId('password').value, '');
  assert.equal(view.byId('confirm').value, '');
  assert.equal(view.stored(LINK_KEY), null);
  assert.equal(view.stored(OUTCOME_KEY), 'done');
  assert.match(view.byId('view-done').textContent, /sign in by typing your new password/);
  assert.equal(view.doc.activeElement, view.byId('view-done').querySelector('h1'));
  assert.equal(view.doc.title, 'Password changed - Expense Tracker');
});

test('a reload after success still says the password was changed', () => {
  // Phones reload background tabs. "Open this page from your reset email",
  // to somebody who has just finished, reads as the reset not having happened.
  const view = open(PAGE, {}, (window) => window.sessionStorage.setItem(OUTCOME_KEY, 'done'));
  assert.deepEqual(view.visible(), ['view-done']);
});

test('a reload after the token was spent without success says the link is dead', () => {
  const view = open(PAGE, {}, (window) => window.sessionStorage.setItem(OUTCOME_KEY, 'spent'));
  assert.deepEqual(view.visible(), ['view-invalid']);
});

test('a new link in the same tab starts over, whatever the last one did', () => {
  const view = open(LINK, {}, (window) => window.sessionStorage.setItem(OUTCOME_KEY, 'done'));
  assert.deepEqual(view.visible(), ['view-form']);
  assert.equal(view.stored(OUTCOME_KEY), null);
});

test('a dead link ends on the page that says how to get a new one', async () => {
  const view = open(LINK, { '/verify': [EXPIRED] });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  await view.submit();

  assert.deepEqual(view.visible(), ['view-invalid']);
  assert.equal(view.byId('password').value, '');
  assert.equal(view.stored(LINK_KEY), null);
  assert.equal(view.stored(OUTCOME_KEY), 'spent');
  const text = view.byId('view-invalid').textContent;
  assert.match(text, /Forgot password\?/);
  // The two ways to arrive here that are not failures at all.
  assert.match(text, /already set a new password with this link/);
  assert.match(text, /newest email/);
  assert.doesNotMatch(text, /has not been changed/);
});

test('the server refusing the password is shown under it, and typing clears it', async () => {
  const view = open(LINK, {
    '/verify': [ok(SESSION)],
    '/user': [refused(422, { code: 422, error_code: 'same_password', msg: 'same' }), ok({})],
    '/logout': [refused(204)],
  });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  await view.submit();

  assert.deepEqual(view.visible(), ['view-form']);
  assert.equal(view.byId('password-error').textContent, page.MESSAGES.same);
  // The token is spent, so a reload must not offer the form again.
  assert.equal(view.stored(LINK_KEY), null);
  assert.equal(view.stored(OUTCOME_KEY), 'spent');

  view.type('password', GOOD + '!');
  assert.equal(view.byId('password-error').textContent, '');
  view.type('confirm', GOOD + '!');
  await view.submit();
  assert.deepEqual(view.visible(), ['view-done']);
  assert.equal(view.stored(OUTCOME_KEY), 'done');
  assert.deepEqual(routes(view.calls), ['POST /verify', 'PUT /user', 'PUT /user', 'POST /logout']);
});

test('no connection shows a banner and the same form works on the retry', async () => {
  const view = open(LINK, {
    '/verify': [new TypeError('Failed to fetch'), ok(SESSION)],
    '/user': [ok({})],
    '/logout': [refused(204)],
  });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  await view.submit();

  assert.deepEqual(view.visible(), ['view-form']);
  assert.equal(view.byId('form-error').textContent, page.MESSAGES.offline);
  assert.equal(view.byId('password').value, GOOD, 'the typed password is kept for the retry');
  assert.equal(view.byId('submit').getAttribute('aria-disabled'), 'false');
  assert.equal(view.byId('submit').textContent, 'Set new password');
  assert.equal(view.stored(LINK_KEY), HASH);
  assert.equal(view.stored(OUTCOME_KEY), null);

  await view.submit();
  assert.deepEqual(view.visible(), ['view-done']);
});

test('an old connection error does not sit beside a new field error', async () => {
  const view = open(LINK, { '/verify': [new TypeError('Failed to fetch')] });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  await view.submit();
  assert.equal(view.byId('form-error').textContent, page.MESSAGES.offline);

  view.type('confirm', GOOD + 'x');
  await view.submit();
  assert.equal(view.byId('confirm-error').textContent, 'Those passwords do not match');
  assert.equal(view.byId('form-error').textContent, '');
});

test('a second press while the first is out sends nothing twice', async () => {
  const view = open(LINK, {
    '/verify': [ok(SESSION)],
    '/user': [ok({})],
    '/logout': [refused(204)],
  });
  view.type('password', GOOD);
  view.type('confirm', GOOD);
  view.press();
  view.press();
  await view.submit();
  assert.deepEqual(routes(view.calls), ['POST /verify', 'PUT /user', 'POST /logout']);
});

test('Show reveals both boxes and Hide covers them again', () => {
  const view = open(LINK);
  const toggle = view.byId('toggle');
  toggle.click();
  assert.equal(view.byId('password').type, 'text');
  assert.equal(view.byId('confirm').type, 'text');
  assert.equal(toggle.textContent, 'Hide');
  assert.equal(toggle.getAttribute('aria-label'), 'Hide password');
  toggle.click();
  assert.equal(view.byId('password').type, 'password');
  assert.equal(view.byId('confirm').type, 'password');
  assert.equal(toggle.textContent, 'Show');
});

test('the page allows itself to talk to the auth server and to nothing else', () => {
  const policy = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  // The whole policy, word for word: a pattern per directive would still pass
  // with "img-src *" added, and that alone is a way to send a token out.
  assert.equal(
    policy,
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
      "connect-src https://ngvsjlgjgsrliqnvmzlr.supabase.co; base-uri 'none'; form-action 'none'",
  );
  // A policy in a meta tag covers only what comes after it.
  const at = html.indexOf('Content-Security-Policy');
  assert.ok(at < html.indexOf('<link'), 'the policy must precede every stylesheet and icon');
  assert.ok(at < html.indexOf('<script'), 'the policy must precede the script');
  // And nothing in the page needs more than that: no inline script or style.
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html), 'inline script');
  assert.ok(!/<style|\sstyle=/.test(html), 'inline style');
  assert.ok(!/\son[a-z]+=/.test(html), 'inline event handler');
});

test('a form that somehow submitted natively would not put the password in an address', () => {
  assert.match(html, /<form id="reset-form" method="post"/);
});
