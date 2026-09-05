# Media assets

Marketing / branding assets for the repo. Regenerate freely; keep sizes as noted.

## `social-preview.svg` / `social-preview.png` (1280×640)

GitHub's social preview — the image shown when the repo link is shared on Reddit, X, Slack, etc.
Upload the preview manually in the repository settings:

> **Repo → Settings → General → Social preview → Edit → Upload** `social-preview.png`.

To regenerate the PNG from the repository root after editing the SVG:

```bash
rsvg-convert -w 1280 -h 640 docs/media/social-preview.svg -o docs/media/social-preview.png
# or: magick -density 144 docs/media/social-preview.svg docs/media/social-preview.png
```

## `demo.gif` (not present)

A demo requires a running, version-matched Burp/extension pair and therefore cannot be produced by the
current static release-documentation pass. No VHS tape is checked into this repository. If a reviewed
tape is added later, run it from the repository root, write the result to `docs/media/demo.gif`, and
then uncomment the demo line near the top of the root `README.md`. Do not present an unrecorded or
unreviewed demo as release evidence.
