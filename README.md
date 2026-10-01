# Expense Tracker - password reset page

The static page behind the "Choose a new password" button in the Expense
Tracker app's reset email. GitHub Pages serves it from `docs/`:

    https://muniprasadan.github.io/expense-tracker/reset/

## How a reset works

1. In the app, **Forgot password?** asks the auth server (Supabase) to send
   a reset email.
2. The button in that email opens
   `reset/#token_hash=<one-time token>&type=recovery`.
3. When the form is submitted the page trades the token for a short-lived
   session, sets the new password with it, and ends every session. The user
   then signs in to the app with the new password.

Nothing is sent until the form is submitted. The token travels in the URL
fragment, so it never reaches this host, and the page may only talk to the
app's Supabase project (see the Content-Security-Policy in
`docs/reset/index.html`).

The Supabase URL and publishable key in `docs/reset/reset.js` are public by
design: the same values ship inside the app. There are no secrets in this
repository.

## What this page is trusted with

Whoever can push to this repository can change what the page does with a new
password, so:

- Keep two-factor authentication on for the GitHub account, and add no
  collaborators or write-scoped deploy tokens that are not needed.
- Do not rename or delete this account or repository while the Supabase reset
  template links here. Change the template first: a renamed address can be
  claimed by somebody else, who would then receive live reset links.
- Every GitHub Pages site of this account shares this page's origin. Do not
  publish third-party script, or a service worker at the root, on any of them.
- Never write the email link with `?token_hash=`. A query string is sent to
  the host; the page reads the fragment (`#`) only and ignores the other form.

## The email template

Supabase > Authentication > Emails > Reset password links to:

    https://muniprasadan.github.io/expense-tracker/reset/#token_hash={{ .TokenHash }}&type=recovery

## Tests

    npm install
    npm test
