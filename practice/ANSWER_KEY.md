# Answer key (don't peek until you've run the checker!)

The checker should produce these results against `practice_server.py`:

| Endpoint | Role | Expected | Correct result | Why |
|---|---|---|---|---|
| /api/profile | anonymous | deny | **FINDING** | Bug 1: no login check |
| /api/profile | alice | allow | PASS | |
| /api/users/1 | anonymous | deny | PASS | Login required here |
| /api/users/1 | alice | allow | PASS | |
| /api/users/2 | bob | allow | PASS | |
| /api/users/1 | bob | deny | **FINDING** | Bug 3: BOLA, bob reads alice's record |
| /api/orders/101 | anonymous | deny | PASS | |
| /api/orders/101 | alice | allow | PASS | Owner |
| /api/orders/101 | bob | deny | PASS | Correct control: 403 |
| /api/orders/101 | admin | allow | PASS | Admin override |
| /api/admin/users | anonymous | deny | PASS | |
| /api/admin/users | alice | deny | **FINDING** | Bug 2: any user sees the admin list |
| /api/admin/users | admin | allow | PASS | |

**Expected total: 3 FINDINGs** (profile without login, bob reading alice, alice reading the admin list).

If you get different results, check the report's HTTP status column first. Then compare it with what the server should return.
