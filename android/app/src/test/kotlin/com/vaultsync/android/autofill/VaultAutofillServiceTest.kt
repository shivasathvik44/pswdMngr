package com.vaultsync.android.autofill

import android.content.Context
import android.view.View
import androidx.test.core.app.ApplicationProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.crypto.BiometricKeyManager
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.model.SessionState
import com.vaultsync.android.model.VaultItem
import com.vaultsync.android.repository.VaultRepository
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class VaultAutofillServiceTest {

    private lateinit var context: Context
    private lateinit var repository: VaultRepository
    private lateinit var keyStoreManager: KeyStoreManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()

        keyStoreManager = KeyStoreManager(context)
        keyStoreManager.isAutofillEnabled = false

        repository = VaultRepository(
            api = ApiClient("http://127.0.0.1:8000"),
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            biometricKeyManager = BiometricKeyManager(context)
        )
    }

    private fun setRepoState(
        accountId: String,
        isAuthenticated: Boolean,
        isUnlocked: Boolean,
        items: List<VaultItem> = emptyList()
    ) {
        val accountField = repository.javaClass.getDeclaredField("accountId").apply { isAccessible = true }
        accountField.set(repository, accountId)

        val sessionStateFlowField = repository.javaClass.getDeclaredField("_sessionState").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val sessionStateFlow = sessionStateFlowField.get(repository) as MutableStateFlow<SessionState>
        sessionStateFlow.value = SessionState(
            serverUrl = "http://127.0.0.1:8000",
            username = "alice",
            accountId = accountId,
            isAuthenticated = isAuthenticated,
            isUnlocked = isUnlocked
        )

        val itemsMapField = repository.javaClass.getDeclaredField("_itemsMap").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val itemsMap = itemsMapField.get(repository) as MutableMap<String, VaultItem>
        itemsMap.clear()
        for (item in items) {
            itemsMap[item.id] = item
        }
    }

    @Test
    fun testOptInPolicy_disabledByDefaultReturnsNull() {
        assertFalse(repository.isAutofillEnabled())

        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true)
        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNull("Autofill must return null when disabled by user", response)
    }

    @Test
    fun testUnauthenticatedSession_returnsNull() {
        repository.setAutofillEnabled(true)
        setRepoState(accountId = "", isAuthenticated = false, isUnlocked = false)

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNull("Unauthenticated session must return null response", response)
    }

    @Test
    fun testMissingTarget_returnsNull() {
        repository.setAutofillEnabled(true)
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true)

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = null,
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNull("Form without target origin must return null response", response)
    }

    @Test
    fun testLockedVault_returnsResponseLevelAuthPrompt() {
        repository.setAutofillEnabled(true)
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = false)

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNotNull("Locked vault must return response-level auth prompt", response)
    }

    @Test
    fun testUnlockedVault_noMatchingItemsReturnsNull() {
        repository.setAutofillEnabled(true)
        val nonMatchingItem = VaultItem(
            id = "item-1",
            title = "Other Site",
            username = "alice",
            password = "pwd",
            url = "https://other.com"
        )
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true, items = listOf(nonMatchingItem))

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNull("Unlocked vault with no matching items must return null", response)
    }

    @Test
    fun testUnlockedVault_matchingItemsReturnsAuthenticatedDatasets() {
        repository.setAutofillEnabled(true)
        val matchingItem = VaultItem(
            id = "item-1",
            title = "Example Login",
            username = "alice@example.com",
            password = "SecretPassword123!",
            url = "https://example.com"
        )
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true, items = listOf(matchingItem))

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNotNull("Unlocked vault with matching item must return response", response)
    }

    @Test
    fun testAppTarget_exactPackageMatching() {
        repository.setAutofillEnabled(true)
        val matchingAppItem = VaultItem(
            id = "app-item-1",
            title = "Target App",
            username = "bob",
            password = "AppPassword123!",
            url = "androidapp://org.example.app"
        )
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true, items = listOf(matchingAppItem))

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.App("org.example.app"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNotNull("Unlocked vault matching app package must return response", response)
    }

    @Test
    fun testDeletedItemsIgnored() {
        repository.setAutofillEnabled(true)
        val deletedItem = VaultItem(
            id = "del-1",
            title = "Deleted Site",
            username = "alice",
            password = "pwd",
            url = "https://example.com",
            isDeleted = true
        )
        setRepoState(accountId = "acc-1", isAuthenticated = true, isUnlocked = true, items = listOf(deletedItem))

        val v1 = View(context)
        val v2 = View(context)
        val form = ParsedAutofillForm(
            target = AutofillTarget.Web("example.com"),
            usernameId = v1.autofillId,
            passwordId = v2.autofillId,
            allFieldIds = listOf(v1.autofillId, v2.autofillId)
        )

        val response = VaultAutofillService.buildFillResponse(context, form, repository)
        assertNull("Deleted vault items must never be offered for autofill", response)
    }

    @Test
    fun testSelfPackageExcludedFromAutofill() {
        assertFalse(
            "Self package must not be accepted as autofill target",
            AutofillOriginMatcher.isValidPackageName("com.vaultsync.android")
        )
        assertFalse(
            "Debug package must not be accepted as autofill target",
            AutofillOriginMatcher.isValidPackageName("com.vaultsync.android.debug")
        )
    }
}
