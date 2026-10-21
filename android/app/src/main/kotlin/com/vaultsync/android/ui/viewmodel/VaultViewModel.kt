package com.vaultsync.android.ui.viewmodel

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vaultsync.android.model.VaultItem
import com.vaultsync.android.repository.VaultRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class VaultUiState(
    val searchQuery: String = "",
    val isLoading: Boolean = false,
    val isSyncing: Boolean = false,
    val errorMessage: String? = null,
    val selectedItem: VaultItem? = null,
    val isPasswordVisible: Boolean = false,
    val clipboardMessage: String? = null
)

class VaultViewModel(
    private val repository: VaultRepository,
    private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(VaultUiState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    private val _items = repository.items
    private var clipboardClearJob: Job? = null
    private var syncJob: Job? = null

    val filteredItems: StateFlow<List<VaultItem>> = combine(_items, _uiState) { items, state ->
        if (state.searchQuery.isBlank()) {
            items
        } else {
            val query = state.searchQuery.trim().lowercase()
            items.filter { item ->
                item.title.lowercase().contains(query) ||
                    item.username.lowercase().contains(query) ||
                    item.url.lowercase().contains(query) ||
                    item.notes.lowercase().contains(query)
            }
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        sync()
    }

    fun onSearchQueryChange(query: String) {
        _uiState.value = _uiState.value.copy(searchQuery = query)
    }

    fun selectItem(item: VaultItem?) {
        _uiState.value = _uiState.value.copy(
            selectedItem = item,
            isPasswordVisible = false,
            errorMessage = null
        )
    }

    fun togglePasswordVisibility() {
        _uiState.value = _uiState.value.copy(
            isPasswordVisible = !_uiState.value.isPasswordVisible
        )
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(errorMessage = null)
    }

    fun clearClipboardMessage() {
        _uiState.value = _uiState.value.copy(clipboardMessage = null)
    }

    fun sync() {
        if (_uiState.value.isSyncing || syncJob?.isActive == true) return
        syncJob = viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isSyncing = true, errorMessage = null)
            try {
                repository.sync()
                _uiState.value = _uiState.value.copy(isSyncing = false)
            } catch (e: CancellationException) {
                _uiState.value = _uiState.value.copy(isSyncing = false)
                throw e
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isSyncing = false,
                    errorMessage = e.message ?: "Sync failed"
                )
            } finally {
                syncJob = null
            }
        }
    }

    fun saveItem(
        id: String?,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        onSuccess: () -> Unit
    ) {
        if (title.isBlank()) {
            _uiState.value = _uiState.value.copy(errorMessage = "Title is required")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val item = if (id != null) {
                    val existing = _items.value.find { it.id == id }
                    VaultItem(
                        id = id,
                        revision = existing?.revision ?: 1,
                        title = title.trim(),
                        username = username.trim(),
                        password = password,
                        url = url.trim(),
                        notes = notes,
                        createdAt = existing?.createdAt ?: java.time.Instant.now().toString(),
                        updatedAt = java.time.Instant.now().toString()
                    )
                } else {
                    VaultItem(
                        title = title.trim(),
                        username = username.trim(),
                        password = password,
                        url = url.trim(),
                        notes = notes
                    )
                }

                repository.saveItem(item)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    selectedItem = item
                )
                onSuccess()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to save item"
                )
            }
        }
    }

    fun deleteItem(id: String, onSuccess: () -> Unit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                repository.deleteItem(id)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    selectedItem = null
                )
                onSuccess()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = e.message ?: "Failed to delete item"
                )
            }
        }
    }

    fun copyToClipboard(label: String, text: String, isSensitive: Boolean = true) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return

        val clip = ClipData.newPlainText(label, text)
        if (isSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)

        val timeoutSeconds = repository.getClipboardTimeoutSeconds()
        _uiState.value = _uiState.value.copy(
            clipboardMessage = if (isSensitive) "$label copied (clearing in ${timeoutSeconds}s)" else "$label copied"
        )

        if (isSensitive && timeoutSeconds > 0) {
            clipboardClearJob?.cancel()
            clipboardClearJob = viewModelScope.launch {
                delay(timeoutSeconds * 1000L)
                val currentClip = clipboard.primaryClip
                if (currentClip != null && currentClip.itemCount > 0) {
                    val currentItem = currentClip.getItemAt(0)
                    if (currentItem.text == text) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            clipboard.clearPrimaryClip()
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                    }
                }
            }
        }
    }

    fun lockVault() {
        repository.lock()
    }
}
