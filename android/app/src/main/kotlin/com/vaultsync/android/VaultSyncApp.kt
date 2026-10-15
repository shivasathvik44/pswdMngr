package com.vaultsync.android

import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.vaultsync.android.model.SessionState
import com.vaultsync.android.repository.VaultRepository
import com.vaultsync.android.ui.screens.ItemDetailScreen
import com.vaultsync.android.ui.screens.ItemEditScreen
import com.vaultsync.android.ui.screens.LoginScreen
import com.vaultsync.android.ui.screens.RegisterScreen
import com.vaultsync.android.ui.screens.ServerConfigScreen
import com.vaultsync.android.ui.screens.SettingsScreen
import com.vaultsync.android.ui.screens.UnlockScreen
import com.vaultsync.android.ui.screens.VaultListScreen
import com.vaultsync.android.ui.theme.VaultSyncTheme
import com.vaultsync.android.ui.viewmodel.AuthViewModel
import com.vaultsync.android.ui.viewmodel.SettingsViewModel
import com.vaultsync.android.ui.viewmodel.VaultViewModel

sealed class Screen {
    object ServerConfig : Screen()
    object Login : Screen()
    object Register : Screen()
    object Unlock : Screen()
    object VaultList : Screen()
    data class ItemDetail(val itemId: String) : Screen()
    data class ItemEdit(val itemId: String?) : Screen()
    object Settings : Screen()
}

@Composable
fun VaultSyncApp(
    repository: VaultRepository,
    authViewModel: AuthViewModel,
    vaultViewModel: VaultViewModel,
    settingsViewModel: SettingsViewModel
) {
    val sessionState by repository.sessionState.collectAsState()
    var currentScreen by remember { mutableStateOf<Screen>(Screen.Login) }

    // Synchronize navigation with session state
    val targetScreen: Screen = when {
        !sessionState.isLoggedIn -> {
            when (currentScreen) {
                is Screen.Register -> Screen.Register
                is Screen.ServerConfig -> Screen.ServerConfig
                else -> Screen.Login
            }
        }
        !sessionState.isUnlocked -> Screen.Unlock
        else -> {
            when (currentScreen) {
                is Screen.Login, is Screen.Register, is Screen.Unlock -> Screen.VaultList
                else -> currentScreen
            }
        }
    }

    VaultSyncTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            Crossfade(targetState = targetScreen, label = "ScreenTransition") { screen ->
                when (screen) {
                    is Screen.ServerConfig -> ServerConfigScreen(
                        authViewModel = authViewModel,
                        onContinue = { currentScreen = Screen.Login }
                    )
                    is Screen.Login -> LoginScreen(
                        authViewModel = authViewModel,
                        onNavigateToRegister = { currentScreen = Screen.Register },
                        onNavigateToServerConfig = { currentScreen = Screen.ServerConfig },
                        onLoginSuccess = { currentScreen = Screen.Unlock }
                    )
                    is Screen.Register -> RegisterScreen(
                        authViewModel = authViewModel,
                        onNavigateToLogin = { currentScreen = Screen.Login },
                        onRegisterSuccess = { currentScreen = Screen.VaultList }
                    )
                    is Screen.Unlock -> UnlockScreen(
                        authViewModel = authViewModel,
                        username = sessionState.username ?: "",
                        onUnlockSuccess = { currentScreen = Screen.VaultList },
                        onLogout = {
                            settingsViewModel.logout()
                            currentScreen = Screen.Login
                        }
                    )
                    is Screen.VaultList -> VaultListScreen(
                        vaultViewModel = vaultViewModel,
                        onNavigateToDetail = { itemId -> currentScreen = Screen.ItemDetail(itemId) },
                        onNavigateToCreate = { currentScreen = Screen.ItemEdit(null) },
                        onNavigateToSettings = { currentScreen = Screen.Settings }
                    )
                    is Screen.ItemDetail -> ItemDetailScreen(
                        vaultViewModel = vaultViewModel,
                        onNavigateBack = { currentScreen = Screen.VaultList },
                        onNavigateToEdit = { itemId -> currentScreen = Screen.ItemEdit(itemId) }
                    )
                    is Screen.ItemEdit -> ItemEditScreen(
                        itemId = screen.itemId,
                        vaultViewModel = vaultViewModel,
                        onNavigateBack = { currentScreen = Screen.VaultList }
                    )
                    is Screen.Settings -> SettingsScreen(
                        settingsViewModel = settingsViewModel,
                        onNavigateBack = { currentScreen = Screen.VaultList },
                        onLogout = { currentScreen = Screen.Login }
                    )
                }
            }
        }
    }
}
