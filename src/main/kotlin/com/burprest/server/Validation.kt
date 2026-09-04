package com.burprest.server

/** Return [value], or reject a missing or blank request parameter with [InvalidParamException]. */
fun requiredParameter(value: String?, name: String): String = when {
    value == null -> throw InvalidParamException("$name is required")
    value.isBlank() -> throw InvalidParamException("$name must not be blank")
    else -> value
}

/** Parse an optional integer. Absence uses [default]; malformed input is never treated as absence. */
fun intParameter(
    value: String?,
    name: String,
    default: Int,
    range: IntRange? = null,
): Int = value?.let { parseInt(it, name) }
    ?.also { validateRange(it, name, range) }
    ?: default.also { validateRange(it, name, range) }

/** Parse an optional integer, preserving absence as null. */
fun optionalIntParameter(
    value: String?,
    name: String,
    range: IntRange? = null,
): Int? = value?.let { parseInt(it, name).also { parsed -> validateRange(parsed, name, range) } }

/** Parse a required integer and optionally enforce an inclusive range. */
fun requiredIntParameter(
    value: String?,
    name: String,
    range: IntRange? = null,
): Int = parseInt(requiredParameter(value, name), name)
    .also { validateRange(it, name, range) }

/** Parse an optional long, preserving absence as null. */
fun optionalLongParameter(
    value: String?,
    name: String,
    range: LongRange? = null,
): Long? = value?.let { parseLong(it, name).also { parsed -> validateRange(parsed, name, range) } }

/** Parse a required long and optionally enforce an inclusive range. */
fun requiredLongParameter(
    value: String?,
    name: String,
    range: LongRange? = null,
): Long = parseLong(requiredParameter(value, name), name)
    .also { validateRange(it, name, range) }

/** Enforce a request-field invariant while returning the validated value for fluent route code. */
inline fun <T> validateParameter(
    value: T,
    name: String,
    requirement: String,
    predicate: (T) -> Boolean,
): T {
    if (!predicate(value)) throw InvalidParamException("$name $requirement")
    return value
}

/** Return a looked-up value, or express its absence as a typed HTTP 404 failure. */
fun <T : Any> requireFound(value: T?, message: String = "resource not found"): T =
    value ?: throw NotFoundException(message)

private fun parseInt(value: String, name: String): Int =
    value.toIntOrNull() ?: throw InvalidParamException("$name must be an integer")

private fun parseLong(value: String, name: String): Long =
    value.toLongOrNull() ?: throw InvalidParamException("$name must be an integer")

private fun validateRange(value: Int, name: String, range: IntRange?) {
    if (range != null && value !in range) {
        throw InvalidParamException("$name must be between ${range.first} and ${range.last}")
    }
}

private fun validateRange(value: Long, name: String, range: LongRange?) {
    if (range != null && value !in range) {
        throw InvalidParamException("$name must be between ${range.first} and ${range.last}")
    }
}
