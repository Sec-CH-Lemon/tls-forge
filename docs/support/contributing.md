# Maintain the documentation

The public site source is `docs/`. MkDocs Material builds a searchable static site at `/docs/`; the landing page in `web/landing/` stays a static source tree. The dated research and measurement archive is `research/` and is not published as website documentation.

The visual shell is in `docs-theme/main.html` and `docs/assets/extra.css`. It uses the landing page's glass panels, colors and local Inter font. The Stripe-inspired UX has sticky section tabs, contextual desktop navigation, a centered reading column and search, aligned tables and examples, and a compact mobile drawer. Guides and Reference both have light and dark themes. Check search, drawer levels, tables and both themes at wide desktop, tablet and narrow mobile widths when editing these files. Source page text remains in Markdown under `docs/`.

The generator dependency is pinned to MkDocs Material 9.8.0. Its announced support end is May 2027; review a migration to the maintained successor before that date.

## Edit and preview

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r docs-requirements.txt
python3 scripts/generate-docs.py --write
.venv-docs/bin/mkdocs serve
```

The generator rebuilds the CLI with the pinned Go module graph and creates these references from source: CLI help, Go exported declarations, Node.js TypeScript declarations, Python public exports and the field inventory of bundled JSON profiles. Guides are edited by hand; generated pages must be regenerated after changing the underlying source.

```bash
python3 scripts/generate-docs.py --check
.venv-docs/bin/mkdocs build --strict --clean
python3 scripts/check-docs-html-links.py
```

`make docs-site-check` runs the same checks. `mkdocs build --strict` checks Markdown links; the HTML-link checker also validates raw HTML cards in the built site. Review the rendered desktop and narrow layouts after visual changes.

## Publication

The [website workflow](https://github.com/Sec-CH-Lemon/tls-forge/blob/development/.github/workflows/landing.yml) generates reference pages, builds the docs, audits the landing page, and publishes one GitHub Pages artifact containing the approved landing source plus `/docs/`. A `landing-v*` tag on `development` approves a new landing source. Documentation changes on `development` republish the most recent approved landing source with newly built docs. Set GitHub Pages source to **GitHub Actions** and custom domain to `tls-forge.com`.

The workflow does not change the direct measurement server at `fp.tls-forge.com`. After a deployment, run Lighthouse against the deployed host for both mobile and desktop; the CI audit covers its local artifact.

When changing a flag, output, or filename, update `README.md`, `[Unreleased]` in `CHANGELOG.md`, and `AGENTS.md` in the same change. Keep feature claims aligned with the code and release state. Preserve raw evidence and its original provenance.
