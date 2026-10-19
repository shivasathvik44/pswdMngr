package com.vaultsync.android.autofill

import com.vaultsync.android.model.VaultItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillOriginMatcherTest {

    private fun itemWithUrl(url: String, isDeleted: Boolean = false): VaultItem {
        return VaultItem(
            id = "test-item-1",
            title = "Test Item",
            username = "alice",
            password = "SecretPassword123!",
            url = url,
            isDeleted = isDeleted
        )
    }

    // ------------------------------------------------------------------------
    // Host Normalization Tests
    // ------------------------------------------------------------------------

    @Test
    fun testNormalizeHost_validDomains() {
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com"))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("EXAMPLE.COM"))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("  example.com.  "))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com:443"))
        assertEquals("login.example.com", AutofillOriginMatcher.normalizeHost("login.example.com:8443"))
        assertEquals("192.168.1.1", AutofillOriginMatcher.normalizeHost("192.168.1.1:8080"))
    }

    @Test
    fun testNormalizeHost_idnDomains() {
        // IDN to Punycode
        val idnHost = "münchen.de"
        val normalized = AutofillOriginMatcher.normalizeHost(idnHost)
        assertEquals("xn--mnchen-3ya.de", normalized)
    }

    @Test
    fun testNormalizeHost_malformedAndDangerousHostsRejected() {
        assertNull(AutofillOriginMatcher.normalizeHost(""))
        assertNull(AutofillOriginMatcher.normalizeHost("   "))
        assertNull(AutofillOriginMatcher.normalizeHost("evil.com/path"))
        assertNull(AutofillOriginMatcher.normalizeHost("user@evil.com"))
        assertNull(AutofillOriginMatcher.normalizeHost("evil.com\\other"))
        assertNull(AutofillOriginMatcher.normalizeHost("evil .com"))
        assertNull(AutofillOriginMatcher.normalizeHost("-invalid.com"))
        assertNull(AutofillOriginMatcher.normalizeHost("invalid-.com"))
        assertNull(AutofillOriginMatcher.normalizeHost("a".repeat(255) + ".com"))
        assertNull(AutofillOriginMatcher.normalizeHost("evil.com?query=1"))
        assertNull(AutofillOriginMatcher.normalizeHost("evil.com#fragment"))
    }

    @Test
    fun testNormalizeHost_userinfoBypassRejected() {
        assertNull("Userinfo containing colon before @ must not be stripped as port",
            AutofillOriginMatcher.normalizeHost("attacker.com:password@legit.com"))
        assertNull(AutofillOriginMatcher.normalizeHost("user:pass@evil.com"))
        assertNull(AutofillOriginMatcher.normalizeHost("admin@bank.com"))
    }

    @Test
    fun testNormalizeHost_portValidation() {
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com:80"))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com:443"))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com:8080"))
        assertEquals("example.com", AutofillOriginMatcher.normalizeHost("example.com:65535"))

        assertNull("Port 0 is invalid", AutofillOriginMatcher.normalizeHost("example.com:0"))
        assertNull("Port > 65535 is invalid", AutofillOriginMatcher.normalizeHost("example.com:65536"))
        assertNull("Port 99999 is invalid", AutofillOriginMatcher.normalizeHost("example.com:99999"))
        assertNull("Non-numeric port is invalid", AutofillOriginMatcher.normalizeHost("example.com:evil"))
        assertNull("Negative port is invalid", AutofillOriginMatcher.normalizeHost("example.com:-80"))
        assertNull("Multiple colons without brackets is invalid", AutofillOriginMatcher.normalizeHost("example.com:80:80"))
    }

    @Test
    fun testNormalizeHost_ipv4OctetBoundaries() {
        assertEquals("192.168.1.1", AutofillOriginMatcher.normalizeHost("192.168.1.1"))
        assertEquals("10.0.0.1", AutofillOriginMatcher.normalizeHost("10.0.0.1"))
        assertEquals("127.0.0.1", AutofillOriginMatcher.normalizeHost("127.0.0.1:8080"))

        assertNull("Octet > 255 rejected", AutofillOriginMatcher.normalizeHost("999.999.999.999"))
        assertNull("Octet 256 rejected", AutofillOriginMatcher.normalizeHost("256.0.0.1"))
        assertNull("Leading zero rejected", AutofillOriginMatcher.normalizeHost("01.02.03.04"))
        assertNull("Incomplete IP rejected", AutofillOriginMatcher.normalizeHost("192.168.1"))
        assertNull("Extra octet rejected", AutofillOriginMatcher.normalizeHost("192.168.1.1.1"))
    }

    @Test
    fun testExtractHostFromUrl_dangerousSchemesRejected() {
        assertNull("javascript: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("javascript:alert(1)"))
        assertNull("data: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("data:text/html,<h1>evil</h1>"))
        assertNull("file: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("file:///etc/passwd"))
        assertNull("ftp: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("ftp://example.com"))
        assertNull("blob: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("blob:https://example.com/123"))
        assertNull("about:blank must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("about:blank"))
        assertNull("content: URI must be rejected",
            AutofillOriginMatcher.extractHostFromUrl("content://media/external/images"))
    }

    @Test
    fun testExtractHostFromUrl_userinfoCleanlyHandled() {
        assertEquals("example.com",
            AutofillOriginMatcher.extractHostFromUrl("https://user:pass@example.com/login"))
        assertEquals("example.com",
            AutofillOriginMatcher.extractHostFromUrl("https://user@example.com/login"))
    }

    // ------------------------------------------------------------------------
    // Web Origin Matching Tests
    // ------------------------------------------------------------------------

    @Test
    fun testWebOrigin_exactMatch() {
        val target = AutofillTarget.Web("example.com")
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("https://example.com")))
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("https://example.com/login")))
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("http://example.com:8080/auth")))
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("example.com")))
    }

    @Test
    fun testWebOrigin_wwwEquivalence() {
        val targetWithWww = AutofillTarget.Web("www.example.com")
        val targetWithoutWww = AutofillTarget.Web("example.com")

        assertTrue(AutofillOriginMatcher.matches(targetWithWww, itemWithUrl("https://example.com")))
        assertTrue(AutofillOriginMatcher.matches(targetWithoutWww, itemWithUrl("https://www.example.com")))
    }

    @Test
    fun testWebOrigin_hostileLookalikesRejected() {
        val target = AutofillTarget.Web("example.com")

        // Substring / suffix injection attacks
        assertFalse("Must not match sub-attacker domain",
            AutofillOriginMatcher.matches(target, itemWithUrl("https://example.com.attacker.com")))
        assertFalse("Must not match prefix-attacker domain",
            AutofillOriginMatcher.matches(target, itemWithUrl("https://attacker-example.com")))
        assertFalse("Must not match character replacement lookalike",
            AutofillOriginMatcher.matches(target, itemWithUrl("https://examp1e.com")))
        assertFalse("Must not match different TLD",
            AutofillOriginMatcher.matches(target, itemWithUrl("https://example.org")))
    }

    @Test
    fun testWebOrigin_subdomainBoundaryPolicy() {
        val target = AutofillTarget.Web("login.example.com")

        // Exact subdomain matches
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("https://login.example.com/")))

        // Different subdomain must NOT match under conservative policy
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("https://payment.example.com/")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("https://admin.login.example.com/")))
    }

    @Test
    fun testWebOrigin_ipLiterals() {
        val target = AutofillTarget.Web("192.168.1.100")

        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("http://192.168.1.100:8000/")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("http://192.168.1.101:8000/")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("http://192.168.1.100.attacker.com/")))
    }

    // ------------------------------------------------------------------------
    // Android App Package Matching Tests
    // ------------------------------------------------------------------------

    @Test
    fun testAppPackage_exactMatch() {
        val target = AutofillTarget.App("com.example.banking")

        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("androidapp://com.example.banking")))
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("app://com.example.banking")))
        assertTrue(AutofillOriginMatcher.matches(target, itemWithUrl("com.example.banking")))
    }

    @Test
    fun testAppPackage_prefixOrSubstringMismatchRejected() {
        val target = AutofillTarget.App("com.example.banking")

        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("com.example.banking.malicious")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("com.example.bankingapp")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("malicious.com.example.banking")))
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("https://banking.com")))
    }

    @Test
    fun testAppPackage_selfAutofillExcluded() {
        assertFalse(AutofillOriginMatcher.isValidPackageName("com.vaultsync.android"))
        assertFalse(AutofillOriginMatcher.isValidPackageName("com.vaultsync.android.debug"))

        val targetSelf = AutofillTarget.App("com.vaultsync.android")
        assertFalse(AutofillOriginMatcher.matches(targetSelf, itemWithUrl("com.vaultsync.android")))
    }

    @Test
    fun testDeletedItem_neverMatches() {
        val target = AutofillTarget.Web("example.com")
        assertFalse(AutofillOriginMatcher.matches(target, itemWithUrl("https://example.com", isDeleted = true)))
    }
}
