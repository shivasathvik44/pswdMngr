package com.vaultsync.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vaultsync.android.ui.viewmodel.VaultViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemDetailScreen(
    vaultViewModel: VaultViewModel,
    onNavigateBack: () -> Unit,
    onNavigateToEdit: (String) -> Unit
) {
    val uiState by vaultViewModel.uiState.collectAsState()
    val item = uiState.selectedItem
    var showDeleteDialog by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(uiState.clipboardMessage) {
        uiState.clipboardMessage?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            vaultViewModel.clearClipboardMessage()
        }
    }

    if (item == null) {
        LaunchedEffect(Unit) {
            onNavigateBack()
        }
        return
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete Vault Item") },
            text = { Text("Are you sure you want to delete \"${item.title}\"? This action cannot be undone.") },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteDialog = false
                        vaultViewModel.deleteItem(item.id) {
                            onNavigateBack()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(item.title) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { onNavigateToEdit(item.id) }) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit Item")
                    }
                    IconButton(onClick = { showDeleteDialog = true }) {
                        Icon(
                            Icons.Default.Delete,
                            contentDescription = "Delete Item",
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            DetailFieldCard(
                label = "Username / Email",
                value = item.username.ifBlank { "—" },
                onCopy = if (item.username.isNotBlank()) {
                    { vaultViewModel.copyToClipboard("Username", item.username, isSensitive = false) }
                } else null
            )

            Spacer(modifier = Modifier.height(12.dp))

            DetailFieldCard(
                label = "Password",
                value = if (uiState.isPasswordVisible) item.password else "••••••••••••",
                isMonospace = true,
                onCopy = { vaultViewModel.copyToClipboard("Password", item.password, isSensitive = true) },
                onToggleVisibility = { vaultViewModel.togglePasswordVisibility() },
                isVisible = uiState.isPasswordVisible
            )

            Spacer(modifier = Modifier.height(12.dp))

            DetailFieldCard(
                label = "Website URL",
                value = item.url.ifBlank { "—" },
                onCopy = if (item.url.isNotBlank()) {
                    { vaultViewModel.copyToClipboard("URL", item.url, isSensitive = false) }
                } else null
            )

            Spacer(modifier = Modifier.height(12.dp))

            DetailFieldCard(
                label = "Notes",
                value = item.notes.ifBlank { "No notes" },
                onCopy = if (item.notes.isNotBlank()) {
                    { vaultViewModel.copyToClipboard("Notes", item.notes, isSensitive = true) }
                } else null
            )

            Spacer(modifier = Modifier.height(16.dp))

            val updatedDate = remember(item.updatedAt) {
                item.updatedAt?.take(16)?.replace('T', ' ') ?: "Never"
            }

            Text(
                text = "Last updated: $updatedDate (revision ${item.revision})",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun DetailFieldCard(
    label: String,
    value: String,
    isMonospace: Boolean = false,
    onCopy: (() -> Unit)? = null,
    onToggleVisibility: (() -> Unit)? = null,
    isVisible: Boolean = false
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = value,
                style = if (isMonospace) MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge
            )
            if (onCopy != null || onToggleVisibility != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    if (onToggleVisibility != null) {
                        OutlinedButton(
                            onClick = onToggleVisibility,
                            modifier = Modifier.height(32.dp)
                        ) {
                            Text(if (isVisible) "Hide" else "Show", style = MaterialTheme.typography.labelSmall)
                        }
                        Spacer(modifier = Modifier.padding(horizontal = 4.dp))
                    }
                    if (onCopy != null) {
                        OutlinedButton(
                            onClick = onCopy,
                            modifier = Modifier.height(32.dp)
                        ) {
                            Text("Copy", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
}
