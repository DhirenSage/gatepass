# Authentication Testing Playbook

1. POST `/api/auth/login` with the admin credentials in `/app/memory/test_credentials.md`.
2. Confirm a bearer token is returned.
3. Call `/api/auth/me` with the bearer token.
4. Confirm invalid credentials return 401.
5. Confirm missing bearer token returns 401.
6. Confirm scanner-only endpoints reject an admin only if the role policy changes; current ADMIN is allowed to operate scanners.