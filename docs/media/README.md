# Media assets

Marketing / branding assets for the repo. Regenerate freely; keep sizes as noted.

## `social-preview.svg` / `social-preview.png` (1280×640)

GitHub's social preview — the image shown when the repo link is shared on Reddit, X, Slack, etc.
GitHub has no API to set it, so upload it **manually**:

> **Repo → Settings → General → Social preview → Edit → Upload** `social-preview.png`.

To regenerate the PNG after editing the SVG:

```bash
rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png
# or: magick -density 144 social-preview.svg social-preview.png
```

## `demo.gif` (to record — the #1 launch asset)

A 20–30s screen capture of the core loop is the single biggest conversion lever for the README and
the Reddit post. It does **not** exist yet because it needs a live Burp on `:8089`.

Record it with [`vhs`](https://github.com/charmbracelet/vhs) using the tape checked into the
launch notes (`burpctl-demo.tape`):

```bash
brew install vhs                 # pulls ttyd + ffmpeg
# start Burp with burp-rest-extension loaded, proxy a couple of requests through it
vhs burpctl-demo.tape            # → burpctl-demo.gif
mv burpctl-demo.gif docs/media/demo.gif
```

Then uncomment the demo line near the top of the root `README.md`.
