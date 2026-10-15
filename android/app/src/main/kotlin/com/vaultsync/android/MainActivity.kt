package com.vaultsync.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.repository.VaultRepository
import com.vaultsync.android.ui.viewmodel.AuthViewModel
import com.vaultsync.android.ui.viewmodel.SettingsViewModel
import com.vaultsync.android.ui.viewmodel.VaultViewModel

class MainActivity : ComponentActivity() {

    private lateinit var repository: VaultRepository
    private lateinit var authViewModel: AuthViewModel
    private lateinit var vaultViewModel: VaultViewModel
    private lateinit var settingsViewModel: SettingsViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots, screen recording, and task switcher snapshots
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        enableEdgeToEdge()

        val keyStoreManager = KeyStoreManager(applicationContext)
        val apiClient = ApiClient(baseUrl = keyStoreManager.serverUrl)
        repository = VaultRepository(
            api = apiClient,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto
        )

        authViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return AuthViewModel(repository) as T
                }
            }
        )[AuthViewModel::class.java]

        vaultViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return VaultViewModel(repository, applicationContext) as T
                }
            }
        )[VaultViewModel::class.java]

        settingsViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return SettingsViewModel(repository) as T
                }
            }
        )[SettingsViewModel::class.java]

        setContent {
            VaultSyncApp(
                repository = repository,
                authViewModel = authViewModel,
                vaultViewModel = vaultViewModel,
                settingsViewModel = settingsViewModel
            )
        }
    }

    override fun onResume() {
        super.onResume()
        repository.checkInactivityLock()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        repository.onUserActivity()
    }
}
