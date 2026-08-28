#!/bin/sh
cat <<'EOF'
============================================================
  SENTINEL X LAB — AUTHORIZED TESTING CONTAINER
  Range: 10.10.10.0/24 (isolated, internal network only)

  Targets:
    gateway   10.10.10.10   (nginx)
    web-app   10.10.10.11   (Flask shop — IDOR / broken auth)
    api       10.10.10.12   (FastAPI — BOLA / BFLA)
    db        10.10.10.13   (PostgreSQL, creds app/app)

  Only run tests inside this network and within your
  approved engagement scope.
============================================================
EOF
exec sleep infinity
