# Detekt baseline

`baseline.xml` records the static-analysis findings that existed when the Detekt gate was first
enforced. Detekt fails the build on any finding **outside** this file, so new code is held to the
full rule set while the pre-existing backlog stays visible instead of being silenced by
`ignoreFailures`.

Regenerate it only when a listed finding has been genuinely fixed or a suppression is deliberately
accepted and reviewed:

```bash
./gradlew detektBaseline
```

Never regenerate the baseline to make a new violation disappear; fix the code instead.
