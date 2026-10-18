package com.vaultsync.android

import android.app.Application
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.crypto.BiometricKeyManager
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.db.VaultDatabase
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
        val biometricKeyManager = BiometricKeyManager(applicationContext)
        val apiClient = ApiClient(baseUrl = keyStoreManager.serverUrl)
        val database = VaultDatabase.getInstance(applicationContext)
        repository = VaultRepository(
            api = apiClient,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = database,
            biometricKeyManager = biometricKeyManager
        )
    }

}
