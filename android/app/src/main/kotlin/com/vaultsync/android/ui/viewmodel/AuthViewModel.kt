package com.vaultsync.android.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vaultsync.android.model.SessionState
import com.vaultsync.android.repository.VaultRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class AuthUiState(
    val serverUrl: String = "http://10.0.2.2:8000",
    val username: String = "",
    val accountPassword: String = "",
    val confirmAccountPassword: String = "",
    val masterPassword: String = "",
    val confirmMasterPassword: String = "",
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val isServerConnected: Boolean? = null
)

class AuthViewModel(
    private val repository: VaultRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(AuthUiState(serverUrl = repository.getServerUrl()))
    val uiState: StateFlow<AuthUiState> = _uiState.asStateFlow()

    val sessionState: StateFlow<SessionState> = repository.sessionState

    fun onServerUrlChange(url: String) {
        _uiState.value = _uiState.value.copy(serverUrl = url, errorMessage = null)
    }

    fun onUsernameChange(name: String) {
        _uiState.value = _uiState.value.copy(username = name, errorMessage = null)
    }

    fun onAccountPasswordChange(pw: String) {
        _uiState.value = _uiState.value.copy(accountPassword = pw, errorMessage = null)
    }

    fun onConfirmAccountPasswordChange(pw: String) {
        _uiState.value = _uiState.value.copy(confirmAccountPassword = pw, errorMessage = null)
    }

    fun onMasterPasswordChange(pw: String) {
        _uiState.value = _uiState.value.copy(masterPassword = pw, errorMessage = null)
    }

    fun onConfirmMasterPasswordChange(pw: String) {
        _uiState.value = _uiState.value.copy(confirmMasterPassword = pw, errorMessage = null)
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(errorMessage = null)
    }

    fun testServerConnection() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                repository.setServerUrl(_uiState.value.serverUrl)
                val health = repository.checkHealth()
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isServerConnected = health.status == "ok"
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isServerConnected = false,
                    errorMessage = e.message ?: "Failed to connect to server"
                )
            }
        }
    }

    fun register(onSuccess: () -> Unit) {
        val state = _uiState.value
        if (state.username.isBlank()) {
            _uiState.value = state.copy(errorMessage = "Username is required")
            return
        }
        if (state.accountPassword.length < 8) {
            _uiState.value = state.copy(errorMessage = "Account password must be at least 8 characters")
            return
        }
        if (state.accountPassword != state.confirmAccountPassword) {
            _uiState.value = state.copy(errorMessage = "Account passwords do not match")
            return
        }
        if (state.masterPassword.length < 8) {
            _uiState.value = state.copy(errorMessage = "Master password must be at least 8 characters")
            return
        }
        if (state.masterPassword != state.confirmMasterPassword) {
            _uiState.value = state.copy(errorMessage = "Master passwords do not match")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            val masterChars = state.masterPassword.toCharArray()
            try {
                repository.setServerUrl(state.serverUrl)
                repository.register(state.username, state.accountPassword, masterChars)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    accountPassword = "",
                    confirmAccountPassword = "",
                    masterPassword = "",
                    confirmMasterPassword = ""
                )
                onSuccess()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Registration failed"
                )
            } finally {
                masterChars.fill('\u0000')
            }
        }
    }

    fun login(onSuccess: () -> Unit) {
        val state = _uiState.value
        if (state.username.isBlank()) {
            _uiState.value = state.copy(errorMessage = "Username is required")
            return
        }
        if (state.accountPassword.isEmpty()) {
            _uiState.value = state.copy(errorMessage = "Account password is required")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                repository.setServerUrl(state.serverUrl)
                repository.login(state.username, state.accountPassword)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    accountPassword = ""
                )
                onSuccess()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Login failed"
                )
            }
        }
    }

    fun unlockVault(onSuccess: () -> Unit) {
        val state = _uiState.value
        if (state.masterPassword.isEmpty()) {
            _uiState.value = state.copy(errorMessage = "Master password is required")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            val masterChars = state.masterPassword.toCharArray()
            try {
                repository.unlock(masterChars)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    masterPassword = ""
                )
                onSuccess()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to unlock vault"
                )
            } finally {
                masterChars.fill('\u0000')
            }
        }
    }

    fun isBiometricUnlockAvailable(): Boolean {
        return repository.isBiometricUnlockAvailable()
    }

    fun getBiometricDecryptCipher(): javax.crypto.Cipher? {
        val accId = repository.accountId
        if (accId.isBlank() || !repository.biometricKeyManager.isBiometricEnabled(accId)) {
            return null
        }
        return try {
            repository.biometricKeyManager.initDecryptCipher(accId)
        } catch (e: com.vaultsync.android.crypto.BiometricKeyInvalidatedException) {
            _uiState.value = _uiState.value.copy(
                errorMessage = "Biometric credentials have changed. Please unlock using your Master Password to re-enable biometrics."
            )
            null
        } catch (e: Exception) {
            _uiState.value = _uiState.value.copy(
                errorMessage = "Failed to initialize biometric unlock: ${e.message}"
            )
            null
        }
    }

    fun unlockWithBiometrics(authenticatedCipher: javax.crypto.Cipher, onSuccess: () -> Unit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val accId = repository.accountId
                val vek = repository.biometricKeyManager.unwrapVek(authenticatedCipher, accId)
                try {
                    repository.unlockWithVek(vek)
                    _uiState.value = _uiState.value.copy(isLoading = false, masterPassword = "")
                    onSuccess()
                } catch (e: Exception) {
                    com.vaultsync.android.crypto.VaultCrypto.clearBytes(vek)
                    throw e
                }
            } catch (e: com.vaultsync.android.crypto.BiometricKeyInvalidatedException) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = "Biometric credentials have changed. Please unlock using your Master Password to re-enable biometrics."
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Biometric unlock failed. Please use your Master Password."
                )
            }
        }
    }
}
