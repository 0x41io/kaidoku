# Rules for AI agents working on kaidoku

- Work on a branch whose name differs from any tag (e.g. `v0.10.4-agpl`, never `v0.10.4`).
- Nothing is merged or tagged until Claude has reviewed it.
- Release checklist: VERSION, README, behavior tests, `pycodestyle --max-line-length=120`, `git diff --check`.

## Licensing (from v0.10.4)

- kaidoku is AGPL-3.0-only from v0.10.4 on; earlier versions stay MIT. New files fall under it: add no MIT headers or other license notices.
- Borrow ideas from other tools (BBOT, ARTEX, ...), never their code: no copying, pasting or translating code from another project, whatever its license, so 0x41 keeps full ownership and can sell or relicense later.
- A new dependency needs its license checked first: MIT, BSD, ISC, Apache-2.0, LGPL, MPL-2.0 and PSF are fine; GPL-2.0-only is not compatible. Name it in the patch description.
- No outside code contributions without a CLA: ask Roi.
