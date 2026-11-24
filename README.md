# API Access Checker - how to use it

This tool checks whether an API blocks the people it should block. It tries each
endpoint as different users (anonymous, user A, user B, admin) and compares what
happened with what you expected.

Only run it against systems you own or have written permission to test, such as
OWASP Juice Shop or crAPI running on your own computer.

## Step 1: Set up a test target
Run a deliberately vulnerable practice app on your machine, for example OWASP Juice Shop
(it runs in Docker or Node). Create two normal test accounts in it.

## Step 2: Get login tokens
Log in as each test user in the app (or with a tool like curl or Burp), and copy the
token (usually a long string called a JWT or bearer token) for each user.

## Step 3: Fill in the config
1. Copy `config.example.json` to `config.json`.
2. Set `base_url` to your lab address.
3. Put the `allowed_hosts` names (for example `localhost`).
4. Replace the `PASTE_..._TOKEN_HERE` values with your tokens.
5. Replace the example endpoints with real ones from your app.

How to read an endpoint entry:
- `path`: the address after the base URL. `{id}` is a placeholder.
- `path_vars`: what fills the placeholder by default.
- `path_vars_by_role`: a different value for a specific user. This is how you test
  whether user B can read user A's record.
- `expect`: for each role, `"allow"` (should work) or `"deny"` (should be blocked).

## Step 4: Preview, then run
```
python3 api_access_check.py config.json --dry-run
python3 api_access_check.py config.json
```
The first command shows what would be sent without sending anything. The second runs
the checks and writes `access_report.md`.

## Step 5: Read the results
- **PASS**: the access rule behaved as expected.
- **FINDING**: a role that should be blocked got data back. Verify it by hand, then
  report it. This is the main thing to look for.
- **UNEXPECTED BLOCK**: a role that should have access was blocked. Check whether your
  expectation was right.
- **CHECK**: the response was something else, such as a 404 or 500. Look at it yourself.

The script exits with code 1 when it finds any FINDING, which is handy for scripts.

## Notes
- Write requests (POST, PUT, PATCH, DELETE) are skipped unless you set
  `"allow_write_requests": true`. Turn that on only in a lab you can reset.
- Keep your tokens out of anything you share publicly. `config.json` contains them.
