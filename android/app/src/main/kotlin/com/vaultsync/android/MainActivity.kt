package com.vaultsync.android

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModelProvider
import com.vaultsync.android.repository.VaultRepository
import com.vaultsync.android.ui.viewmodel.AuthViewModel
import com.vaultsync.android.ui.viewmodel.SettingsViewModel
import com.vaultsync.android.ui.viewmodel.VaultViewModel
import com.vaultsync.android.ui.viewmodel.VaultViewModelFactory

class MainActivity : FragmentActivity() {

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

        repository = (application as VaultSyncApplication).repository

        val factory = VaultViewModelFactory(repository) { applicationContext }

        authViewModel = ViewModelProvider(this, factory)[AuthViewModel::class.java]
        vaultViewModel = ViewModelProvider(this, factory)[VaultViewModel::class.java]
        settingsViewModel = ViewModelProvider(this, factory)[SettingsViewModel::class.java]

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
