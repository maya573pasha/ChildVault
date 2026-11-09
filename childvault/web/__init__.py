"""
childvault.web - small local web UI (Phase 4).

Each teammate adds their pages as a separate module with its own
APIRouter, then registers it in app.create_app():
    app.py      app factory, security headers, home page   (Mariyam)
    html.py     safe HTML layout + esc()                   (Mariyam)
    auth.py    login / logout / sessions      (Mariyam)
    lookup.py   pseudonym lookup page          (Mariyam)
    files.py    upload / open / revoke         (Aaleen)
    share.py    share-bundle page              (Laiba)
    audit.py    audit-log viewer               (Laiba)
"""
