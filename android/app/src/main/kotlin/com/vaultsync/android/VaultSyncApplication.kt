package com.vaultsync.android

import android.app.Application
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.repository.VaultRepository

/**
 * VaultSync application class managing the application-scoped repository and lifecycle.
 */
class VaultSyncApplication : Application() {

    lateinit var repository: VaultRepository
        private set

    override fun onCreate() {
        super.onCreate()
        initRepository()
    }

    private fun initRepository() {
        val keyStoreManager = KeyStoreManager(applicationContext)
        val apiClient = ApiClient(baseUrl = keyStoreManager.serverUrl)
        repository = VaultRepository(
            api = apiClient,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto
        )
    }

}
