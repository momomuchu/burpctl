package com.burprest

/**
 * The single source of truth for the version this extension reports.
 *
 * `/health`, `/version`, the loaded-extension banner, the served OpenAPI document and the `bp`
 * package all publish this same value, so a deployed JAR can never claim a version that its
 * behavior does not match. `BuildIdentityTest` and `bp/tests/test_release_identity.py` fail if any
 * of those copies drift.
 */
const val EXTENSION_VERSION: String = "2.0.0"

/** Product name reported by `/version`. */
const val EXTENSION_NAME: String = "burp-rest-extension"
