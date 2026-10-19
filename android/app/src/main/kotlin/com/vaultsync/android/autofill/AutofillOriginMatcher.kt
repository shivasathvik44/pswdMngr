package com.vaultsync.android.autofill

import com.vaultsync.android.model.VaultItem
import java.net.IDN
import java.net.URI

/**
 * Target entity representing the origin of an Autofill request.
 */
sealed class AutofillTarget {
    data class Web(val host: String) : AutofillTarget()
    data class App(val packageName: String) : AutofillTarget()
}

/**
 * Origin and credential matching engine for Android Autofill.
 *
 * Security Invariants:
 * 1. Conservative Matching: Prefer exact host matches. Substrings, arbitrary regex,
 *    and fuzzy matching are strictly forbidden.
 * 2. Host Normalization: Hosts are lowercased, stripped of trailing dots, stripped of ports,
 *    and converted to Punycode ASCII via IDN.
 * 3. Strict Boundary Checks: Hostile lookalike or suffix injection domains
 *    (e.g., "example.com.attacker.com") must NEVER match "example.com".
 * 4. App Isolation: Android package names must conform to valid Android package identifiers
 *    and match exactly. VaultSync's own package is excluded from autofill targets.
 */
object AutofillOriginMatcher {

    private val PACKAGE_NAME_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")
    private val HOST_CHAR_REGEX = Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
    private val IPV4_REGEX = Regex("^(\\d{1,3}\\.){3}\\d{1,3}$")

    private val EXCLUDED_PACKAGES = setOf(
        "com.vaultsync.android",
        "com.vaultsync.android.debug"
    )

    /**
     * Normalize a raw hostname into a canonical ASCII Punycode host.
     * Returns null if the host is malformed, invalid, or contains forbidden characters.
     */
    fun normalizeHost(rawHost: String?): String? {
        if (rawHost.isNullOrBlank()) return null
        var h = rawHost.trim().lowercase()

        // 1. Strict rejection of user-info components (@) and forbidden path/query/control characters
        if (h.contains('@') || h.contains('/') || h.contains('\\') ||
            h.contains(' ') || h.contains('?') || h.contains('#')
        ) {
            return null
        }

        // 2. Port validation & stripping
        // Handles IPv6 bracket notation [::1]:8080 vs regular host:8080
        if (h.startsWith('[')) {
            val closingBracket = h.indexOf(']')
            if (closingBracket == -1) return null
            val ipv6Content = h.substring(1, closingBracket)
            val remainder = h.substring(closingBracket + 1)
            if (remainder.isNotEmpty()) {
                if (!remainder.startsWith(':')) return null
                val portStr = remainder.substring(1)
                val port = portStr.toIntOrNull() ?: return null
                if (port !in 1..65535) return null
            }
            if (ipv6Content.isBlank() || !isValidIpv6(ipv6Content)) return null
            return "[$ipv6Content]"
        } else if (h.contains(':')) {
            val colonIdx = h.indexOf(':')
            val portStr = h.substring(colonIdx + 1)
            // Multiple colons without brackets is invalid
            if (portStr.contains(':')) return null
            val port = portStr.toIntOrNull() ?: return null
            if (port !in 1..65535) return null
            h = h.substring(0, colonIdx)
        }

        // 3. Strip trailing dots (FQDN root notation)
        h = h.trimEnd('.')
        if (h.isBlank()) return null

        // 4. Validate numeric dot-separated hosts (IPv4 candidates) and reject numeric TLDs
        if (h.all { it.isDigit() || it == '.' }) {
            return if (isValidIpv4(h)) h else null
        }
        if (h.contains('.') && h.substringAfterLast('.').all { it.isDigit() }) {
            return null
        }

        // 5. Convert Internationalized Domain Name (IDN) to ASCII Punycode
        val asciiHost = try {
            IDN.toASCII(h, IDN.ALLOW_UNASSIGNED or IDN.USE_STD3_ASCII_RULES)
        } catch (_: Exception) {
            return null
        }

        if (asciiHost.length > 253) return null

        // 6. Validate RFC 1035 label syntax
        if (!HOST_CHAR_REGEX.matches(asciiHost)) {
            return null
        }

        val labels = asciiHost.split('.')
        for (label in labels) {
            if (label.isEmpty() || label.length > 63 || label.startsWith('-') || label.endsWith('-')) {
                return null
            }
        }

        return asciiHost
    }

    private fun isValidIpv4(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            val num = part.toIntOrNull() ?: return@all false
            num in 0..255 && (part == "0" || !part.startsWith("0"))
        }
    }

    private fun isValidIpv6(host: String): Boolean {
        if (host.length > 39) return false
        val segments = host.split(':')
        if (segments.size > 8) return false
        return host.all { it in '0'..'9' || it in 'a'..'f' || it == ':' }
    }

    /**
     * Extract a normalized host from a vault item's URL field.
     * Supports both web URLs (https://example.com) and plain host strings (example.com).
     */
    fun extractHostFromUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val trimmed = url.trim()

        val lower = trimmed.lowercase()
        // Reject non-web or dangerous schemes immediately
        if (lower.startsWith("androidapp://") || lower.startsWith("app://") ||
            lower.startsWith("javascript:") || lower.startsWith("data:") ||
            lower.startsWith("file:") || lower.startsWith("content:") ||
            lower.startsWith("about:") || lower.startsWith("blob:")
        ) {
            return null
        }

        if (trimmed.contains("://")) {
            val scheme = trimmed.substringBefore("://").lowercase()
            if (scheme != "http" && scheme != "https") {
                return null
            }
        }

        return try {
            val uri = if (trimmed.contains("://")) URI(trimmed) else URI("https://$trimmed")
            val host = uri.host ?: uri.authority?.substringBefore('@')?.substringBefore(':')
            normalizeHost(host)
        } catch (_: Exception) {
            val candidate = trimmed.substringBefore('/').substringBefore('?')
            normalizeHost(candidate)
        }
    }

    /**
     * Extract an Android application package name from a vault item's URL field.
     */
    fun extractPackageFromUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val trimmed = url.trim()

        val candidate = when {
            trimmed.startsWith("androidapp://") -> trimmed.removePrefix("androidapp://").substringBefore('/')
            trimmed.startsWith("app://") -> trimmed.removePrefix("app://").substringBefore('/')
            PACKAGE_NAME_REGEX.matches(trimmed) -> trimmed
            else -> null
        } ?: return null

        return if (isValidPackageName(candidate)) candidate else null
    }

    /**
     * Validate an Android application package name.
     */
    fun isValidPackageName(packageName: String?): Boolean {
        if (packageName.isNullOrBlank()) return false
        val p = packageName.trim()
        if (p.length > 256) return false
        if (EXCLUDED_PACKAGES.contains(p)) return false
        return PACKAGE_NAME_REGEX.matches(p)
    }

    /**
     * Determine whether a vault item matches the target origin under the conservative policy.
     */
    fun matches(target: AutofillTarget, item: VaultItem): Boolean {
        if (item.isDeleted) return false

        return when (target) {
            is AutofillTarget.Web -> matchesWeb(target.host, item)
            is AutofillTarget.App -> matchesApp(target.packageName, item)
        }
    }

    private fun matchesWeb(targetHost: String, item: VaultItem): Boolean {
        val normalizedTarget = normalizeHost(targetHost) ?: return false
        val itemHost = extractHostFromUrl(item.url) ?: return false

        // Exact match
        if (normalizedTarget == itemHost) return true

        // www. prefix equivalence: www.example.com == example.com
        val targetWithoutWww = normalizedTarget.removePrefix("www.")
        val itemWithoutWww = itemHost.removePrefix("www.")
        if (targetWithoutWww == itemWithoutWww) return true

        return false
    }

    private fun matchesApp(targetPackage: String, item: VaultItem): Boolean {
        if (!isValidPackageName(targetPackage)) return false
        val itemPackage = extractPackageFromUrl(item.url) ?: return false

        // Exact package match only
        return targetPackage == itemPackage
    }
}
