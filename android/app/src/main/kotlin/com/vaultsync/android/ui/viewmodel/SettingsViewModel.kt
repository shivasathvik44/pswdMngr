package com.vaultsync.android.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vaultsync.android.repository.VaultRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SettingsUiState(
    val serverUrl: String = "",
    val username: String = "",
    val autoLockTimeoutMinutes: Int = 5,
    val clipboardTimeoutSeconds: Int = 30,
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val showChangeAccountPasswordDialog: Boolean = false,
    val showRotateMasterPasswordDialog: Boolean = false,
    val isBiometricEnabled: Boolean = false,
    val isAutofillEnabled: Boolean = false
)

class SettingsViewModel(
    private val repository: VaultRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            serverUrl = repository.getServerUrl(),
            username = repository.sessionState.value.username ?: "",
            autoLockTimeoutMinutes = repository.getAutoLockTimeoutMinutes(),
            clipboardTimeoutSeconds = repository.getClipboardTimeoutSeconds(),
            isBiometricEnabled = if (repository.accountId.isNotBlank()) repository.biometricKeyManager.isBiometricEnabled(repository.accountId) else false,
            isAutofillEnabled = repository.isAutofillEnabled()
        )
    )
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    fun updateAutoLockTimeout(minutes: Int) {
        repository.setAutoLockTimeoutMinutes(minutes)
        _uiState.value = _uiState.value.copy(autoLockTimeoutMinutes = minutes)
    }

    fun updateClipboardTimeout(seconds: Int) {
        repository.setClipboardTimeoutSeconds(seconds)
        _uiState.value = _uiState.value.copy(clipboardTimeoutSeconds = seconds)
    }

    fun clearMessages() {
        _uiState.value = _uiState.value.copy(errorMessage = null, successMessage = null)
    }

    fun showChangeAccountPasswordDialog(show: Boolean) {
        _uiState.value = _uiState.value.copy(showChangeAccountPasswordDialog = show, errorMessage = null)
    }

    fun showRotateMasterPasswordDialog(show: Boolean) {
        _uiState.value = _uiState.value.copy(showRotateMasterPasswordDialog = show, errorMessage = null)
    }

    fun changeAccountPassword(currentPass: String, newPass: String, confirmPass: String) {
        if (_uiState.value.isLoading) return
        if (currentPass.isEmpty()) {
            _uiState.value = _uiState.value.copy(errorMessage = "Current password is required")
            return
        }
        if (newPass.length < 8) {
            _uiState.value = _uiState.value.copy(errorMessage = "New password must be at least 8 characters")
            return
        }
        if (newPass != confirmPass) {
            _uiState.value = _uiState.value.copy(errorMessage = "New passwords do not match")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                repository.changeAccountPassword(currentPass, newPass)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    showChangeAccountPasswordDialog = false,
                    successMessage = "Account password updated successfully"
                )
            } catch (e: CancellationException) {
                _uiState.value = _uiState.value.copy(isLoading = false)
                throw e
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to change account password"
                )
            }
        }
    }

    fun rotateMasterPassword(currentMaster: String, newMaster: String, confirmMaster: String) {
        if (_uiState.value.isLoading) return
        if (currentMaster.isEmpty()) {
            _uiState.value = _uiState.value.copy(errorMessage = "Current master password is required")
            return
        }
        if (newMaster.length < 8) {
            _uiState.value = _uiState.value.copy(errorMessage = "New master password must be at least 8 characters")
            return
        }
        if (newMaster != confirmMaster) {
            _uiState.value = _uiState.value.copy(errorMessage = "New master passwords do not match")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            val currentChars = currentMaster.toCharArray()
            val newChars = newMaster.toCharArray()
            try {
                repository.rotateMasterPassword(currentChars, newChars)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    showRotateMasterPasswordDialog = false,
                    successMessage = "Master password rotated successfully"
                )
            } catch (e: CancellationException) {
                _uiState.value = _uiState.value.copy(isLoading = false)
                throw e
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to rotate master password"
                )
            } finally {
                currentChars.fill('\u0000')
                newChars.fill('\u0000')
            }
        }
    }

    fun logout() {
        viewModelScope.launch {
            repository.logout()
        }
    }

    fun lock() {
        repository.lock()
    }

    fun isBiometricEnabled(): Boolean {
        val accId = repository.accountId
        return accId.isNotBlank() && repository.biometricKeyManager.isBiometricEnabled(accId)
    }

    fun canEnableBiometric(): Boolean {
        return repository.canEnableBiometric()
    }

    fun getBiometricEncryptCipher(): javax.crypto.Cipher? {
        val accId = repository.accountId
        if (accId.isBlank()) return null
        return try {
            repository.biometricKeyManager.initEncryptCipher(accId)
        } catch (e: Exception) {
            _uiState.value = _uiState.value.copy(errorMessage = "Failed to initialize biometric enrollment: ${e.message}")
            null
        }
    }

    fun enableBiometric(authenticatedCipher: javax.crypto.Cipher) {
        if (_uiState.value.isLoading) return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                repository.enableBiometricUnlock(authenticatedCipher)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isBiometricEnabled = true,
                    successMessage = "Biometric unlock enabled successfully"
                )
            } catch (e: CancellationException) {
                _uiState.value = _uiState.value.copy(isLoading = false)
                throw e
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to enable biometric unlock"
                )
            }
        }
    }

    fun disableBiometric() {
        viewModelScope.launch {
            repository.disableBiometricUnlock()
            _uiState.value = _uiState.value.copy(
                isBiometricEnabled = false,
                successMessage = "Biometric unlock disabled"
            )
        }
    }

    fun updateAutofillEnabled(enabled: Boolean) {
        repository.setAutofillEnabled(enabled)
        _uiState.value = _uiState.value.copy(
            isAutofillEnabled = enabled,
            successMessage = if (enabled) "VaultSync Autofill enabled" else "VaultSync Autofill disabled"
        )
    }
}
