# Upstream maintenance policy

- Upstream remote: `https://github.com/Ylianst/MeshCentral.git`.
- Commando changes remain under `commando/` except for the reviewed `meshctrl.js --tlsstrict` and `--loginpassfile` options. Changes to upstream transport, authentication and agent code require security review.
- Production builds pin a reviewed upstream commit and Commando image version. Never deploy `master` or `latest` tags directly.
- Review upstream releases and security advisories weekly. Critical fixes receive immediate assessment; normal upgrades use a monthly candidate and quarterly production window.
- Every update must pass broker tests, image build, agent enrollment, desktop/terminal/files, expiry, local revocation, portal revocation, reboot recovery and backup restore.
- Retain Apache-2.0 license and attribution notices.
