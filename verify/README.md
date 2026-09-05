# Live release verification

`run_live.py` asks whether the deployed Burp extension and `bp` CLI match the current release tree. It uses only Python's standard library, the existing CLI environment, `git`, `ps`, and `lsof`. It never runs Gradle.

## Run

Obtain the expected SHA-256 from the independently designated build/release artifact. Do not derive it from the extension path returned by the running system; that would compare the artifact to itself.

```sh
cd /path/to/burpctl
python3 verify/run_live.py \
  --expected-jar-sha256 "$RELEASE_ARTIFACT_SHA256" \
  --exclusive-extension-custody
```

`--exclusive-extension-custody` is required before cases may mutate the extension session or H2 history. It means no other actor or process will use those resources during the run. Without it, affected cases become `COULD_NOT_RUN`; the suite never assumes exclusivity from an empty read alone.

A local harness check (no Burp request is sent) is also available:

```sh
python3 -m unittest verify/test_run_live.py
```

The default run selects both behavior groups. They can be run separately:

```sh
python3 verify/run_live.py --expected-jar-sha256 "$RELEASE_ARTIFACT_SHA256" --group rest --exclusive-extension-custody
python3 verify/run_live.py --expected-jar-sha256 "$RELEASE_ARTIFACT_SHA256" --group cli
```

Use repeatable `--case REST-001` for an exact subset. A selection matching zero behavior cases writes `HARNESS-000`, exits nonzero, and cannot look clean. `--defer-case CASE_ID=REASON` records an explicit `COULD_NOT_RUN`; it does not silently omit the case.

The default owned targets bind literal `127.0.0.1:9931` and `:9932`. Override them with `--target-a-port` and `--target-b-port`. A pre-existing listener is never reused or stopped: cases needing that target become `COULD_NOT_RUN`. Both servers are stopped in the outer `finally`; thread termination and successful port rebinding are the release oracle.

## Release gates

Every nonempty run performs these gates before behavior:

1. Parse six product-owned versions from `bp/pyproject.toml`, `bp/src/bp/__init__.py`, `bp/uv.lock`, `build.gradle.kts`, `BuildIdentity.kt`, and `openapi.json`; require one strict semantic version.
2. Join the `127.0.0.1:8089` listener PID to Burp's `--user-config-file`, select its one loaded matching Java extension, and hash the JAR through a no-follow file descriptor.
3. Compare that observed digest with the independent `--expected-jar-sha256` input.
4. Require `/extensions` to self-report the same enabled path.
5. Only after version consensus, require `/health` to return that version and a valid uptime.
6. Compare the JAR-embedded OpenAPI document structurally with the source document. A mismatch is fatal: every selected behavior case is recorded `COULD_NOT_RUN` because the deployed binary predates the release tree.
7. Sample uptime throughout and repeat the JAR file identity/hash and source/CLI/docs/verifier digests after the run. A reset or changed input invalidates every behavior verdict.

A file replacement is not a proven redeploy. Under `auto_reload:false`, require an authoritative uptime reset after deployment and then rerun all path/hash/self-report gates with the new independent artifact digest.

## Custody and effects

The verifier never calls `PUT /config/user`, imports any Burp configuration, changes scope or interception, clears proxy history, starts Scanner/Intruder work, or contacts Collaborator, DNS, or any non-loopback host.

Outbound cases require extension H2 history and sitemap to be empty under asserted exclusive custody. After each case, the verifier refuses global deletion if an entry is not attributable to this run's owned target marker, otherwise clears and re-reads both resources as empty. Session cases similarly require a clean baseline, clear it in `finally`, and re-read session and cookie jar. Any unconfirmed cleanup produces unknown custody and a containment abort; all forfeited cases are emitted as `COULD_NOT_RUN`.

Project configuration content, ambient history rows, and sitemap rows are never written into results. Credentials are not used; target and session values are fresh inert markers.

## Results

Each run atomically writes `verify/results/live-<UTC>.json` (or `--result verify/results/<name>.json`) and prints its path plus summary. The format is described by `verify/result-schema.json`. Every case records:

- invariant and assertion;
- `PASS`, `FAIL`, or `COULD_NOT_RUN`;
- bounded observed evidence;
- every touched resource's disposition.

A clean exit requires at least one behavior case executed, no behavior failures, no `COULD_NOT_RUN`, and no failed system gate. Results record the repository commit, dirty paths, aggregate source/docs/CLI hashes, exact CLI source-file hashes, verifier hash, configured JAR path and pre/post file snapshots, all uptime samples, final resource custody, and the proof ceiling.

## Proof ceiling

The process/config join, Montoya self-reported filename, stable device/inode/mtime/size/hash, and monotonic uptime attribute observations to one unchanged configured artifact path. They do not independently attest the JAR bytes already loaded in JVM memory. Closing that gap requires a product change: compute an immutable JAR digest and fresh instance nonce at extension initialization and expose both live.

The suite does not establish Collaborator behavior, active Scanner/Intruder lifecycle, raw HTTP framing, browser behavior, completeness or secrecy of ambient Burp data, or any behavior case blocked by an artifact/source preflight mismatch.
