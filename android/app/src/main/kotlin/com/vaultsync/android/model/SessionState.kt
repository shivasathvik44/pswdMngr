package com.vaultsync.android.model

/**
 * Observable session and vault lifecycle state.
 */
data class SessionState(
    val serverUrl: String = "http://10.0.2.2:8000",
    val username: String = "",
    val accountId: String = "",
    val isAuthenticated: Boolean = false,
    val isUnlocked: Boolean = false,
    val lockGeneration: Int = 0,
    val autoLockMinutes: Int = 5,
    val itemCount: Int = 0,
    val corruptedRecordCount: Int = 0,
    val isSyncing: Boolean = false,
    val syncStatusMessage: String = "Synced",
    val errorMessage: String? = null,
    val warningMessage: String? = null,
    val isBiometricEnabled: Boolean = false,
    val isBiometricAvailable: Boolean = false
) {
    val isLoggedIn: Boolean
        get() = isAuthenticated
}
