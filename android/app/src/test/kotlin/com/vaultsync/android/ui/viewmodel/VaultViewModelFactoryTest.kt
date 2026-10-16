package com.vaultsync.android.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.repository.VaultRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class VaultViewModelFactoryTest {

    private lateinit var repository: VaultRepository
    private lateinit var factory: VaultViewModelFactory

    @Before
    fun setUp() {
        val keyStoreManager = KeyStoreManager(context = null)
        val apiClient = ApiClient(baseUrl = "http://127.0.0.1:8000")
        repository = VaultRepository(
            api = apiClient,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto
        )
        factory = VaultViewModelFactory(repository) { error("No Android context needed for these ViewModels") }
    }

    @Test
    fun testAuthAndSettingsObserveSharedRepository() {
        val authVm = factory.create(AuthViewModel::class.java)
        val settingsVm = factory.create(SettingsViewModel::class.java)

        assertNotNull(authVm)
        assertNotNull(settingsVm)
        settingsVm.updateAutoLockTimeout(9)
        assertEquals(9, repository.getAutoLockTimeoutMinutes())

        // Verify shared repository state observation
        assertSame(repository.sessionState, authVm.sessionState)
    }

    @Test
    fun testSimulatedActivityRecreationPreservesViewModelAndRepositoryIdentity() {
        // ViewModelStore simulates Activity configuration recreation retention
        val viewModelStore = ViewModelStore()

        // First Activity lifecycle:
        val providerActivity1 = ViewModelProvider(viewModelStore, factory)
        val authVmActivity1 = providerActivity1[AuthViewModel::class.java]
        val vaultVmActivity1 = providerActivity1[SettingsViewModel::class.java]

        // Second Activity lifecycle after configuration change (shares same ViewModelStore and App Repository):
        val recreatedFactory = VaultViewModelFactory(repository) { error("No Android context needed") }
        val providerActivity2 = ViewModelProvider(viewModelStore, recreatedFactory)
        val authVmActivity2 = providerActivity2[AuthViewModel::class.java]
        val vaultVmActivity2 = providerActivity2[SettingsViewModel::class.java]

        // The ViewModels must be identical retained instances
        assertSame(authVmActivity1, authVmActivity2)
        assertSame(vaultVmActivity1, vaultVmActivity2)

        // Both ViewModels observe the exact same repository session state
        assertSame(repository.sessionState, authVmActivity2.sessionState)

        viewModelStore.clear()
    }

    class UnknownViewModel : ViewModel()

    @Test
    fun testUnsupportedViewModelClassThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException::class.java) {
            factory.create(UnknownViewModel::class.java)
        }
    }
}
