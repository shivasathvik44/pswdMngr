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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.vaultsync.android.ui.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    settingsViewModel: SettingsViewModel,
    onNavigateBack: () -> Unit,
    onLogout: () -> Unit
) {
    val uiState by settingsViewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let { err ->
            snackbarHostState.showSnackbar(err)
            settingsViewModel.clearMessages()
        }
    }

    LaunchedEffect(uiState.successMessage) {
        uiState.successMessage?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            settingsViewModel.clearMessages()
        }
    }

    // Change Account Password Dialog
    if (uiState.showChangeAccountPasswordDialog) {
        var currentPass by remember { mutableStateOf("") }
        var newPass by remember { mutableStateOf("") }
        var confirmPass by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { settingsViewModel.showChangeAccountPasswordDialog(false) },
            title = { Text("Change Account Password") },
            text = {
                Column {
                    Text(
                        text = "This changes the authentication password used to log in to the server.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = currentPass,
                        onValueChange = { currentPass = it },
                        label = { Text("Current Password") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newPass,
                        onValueChange = { newPass = it },
                        label = { Text("New Password (min 8 chars)") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirmPass,
                        onValueChange = { confirmPass = it },
                        label = { Text("Confirm New Password") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        settingsViewModel.changeAccountPassword(currentPass, newPass, confirmPass)
                    },
                    enabled = !uiState.isLoading
                ) {
                    Text("Change Password")
                }
            },
            dismissButton = {
                TextButton(onClick = { settingsViewModel.showChangeAccountPasswordDialog(false) }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Rotate Master Password Dialog
    if (uiState.showRotateMasterPasswordDialog) {
        var currentMaster by remember { mutableStateOf("") }
        var newMaster by remember { mutableStateOf("") }
        var confirmMaster by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { settingsViewModel.showRotateMasterPasswordDialog(false) },
            title = { Text("Rotate Master Password") },
            text = {
                Column {
                    Text(
                        text = "This re-encrypts your Vault Encryption Key (VEK) with a new master key. Your encrypted vault records remain safe.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = currentMaster,
                        onValueChange = { currentMaster = it },
                        label = { Text("Current Master Password") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newMaster,
                        onValueChange = { newMaster = it },
                        label = { Text("New Master Password (min 8 chars)") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirmMaster,
                        onValueChange = { confirmMaster = it },
                        label = { Text("Confirm New Master Password") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        settingsViewModel.rotateMasterPassword(currentMaster, newMaster, confirmMaster)
                    },
                    enabled = !uiState.isLoading
                ) {
                    Text("Rotate Key")
                }
            },
            dismissButton = {
                TextButton(onClick = { settingsViewModel.showRotateMasterPasswordDialog(false) }) {
                    Text("Cancel")
                }
            }
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
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
            Text(
                text = "Account & Server",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(text = "Username", style = MaterialTheme.typography.labelSmall)
                    Text(text = uiState.username.ifBlank { "Not signed in" }, style = MaterialTheme.typography.bodyLarge)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(text = "Server URL", style = MaterialTheme.typography.labelSmall)
                    Text(text = uiState.serverUrl, style = MaterialTheme.typography.bodyMedium)
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Security & Timeouts",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // Auto-lock options
                    var autoLockExpanded by remember { mutableStateOf(false) }
                    val autoLockOptions = listOf(1, 5, 15, 30, 0)

                    Text(text = "Auto-Lock Inactivity Timeout", style = MaterialTheme.typography.labelMedium)
                    Spacer(modifier = Modifier.height(4.dp))

                    ExposedDropdownMenuBox(
                        expanded = autoLockExpanded,
                        onExpandedChange = { autoLockExpanded = !autoLockExpanded }
                    ) {
                        OutlinedTextField(
                            value = if (uiState.autoLockTimeoutMinutes == 0) "Disabled" else "${uiState.autoLockTimeoutMinutes} minutes",
                            onValueChange = {},
                            readOnly = true,
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = autoLockExpanded) },
                            modifier = Modifier.fillMaxWidth().menuAnchor()
                        )
                        ExposedDropdownMenu(
                            expanded = autoLockExpanded,
                            onDismissRequest = { autoLockExpanded = false }
                        ) {
                            autoLockOptions.forEach { mins ->
                                DropdownMenuItem(
                                    text = { Text(if (mins == 0) "Never / Disabled" else "$mins minutes") },
                                    onClick = {
                                        settingsViewModel.updateAutoLockTimeout(mins)
                                        autoLockExpanded = false
                                    }
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Clipboard options
                    var clipboardExpanded by remember { mutableStateOf(false) }
                    val clipboardOptions = listOf(15, 30, 60, 120, 0)

                    Text(text = "Clipboard Auto-Clear Timeout", style = MaterialTheme.typography.labelMedium)
                    Spacer(modifier = Modifier.height(4.dp))

                    ExposedDropdownMenuBox(
                        expanded = clipboardExpanded,
                        onExpandedChange = { clipboardExpanded = !clipboardExpanded }
                    ) {
                        OutlinedTextField(
                            value = if (uiState.clipboardTimeoutSeconds == 0) "Disabled" else "${uiState.clipboardTimeoutSeconds} seconds",
                            onValueChange = {},
                            readOnly = true,
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = clipboardExpanded) },
                            modifier = Modifier.fillMaxWidth().menuAnchor()
                        )
                        ExposedDropdownMenu(
                            expanded = clipboardExpanded,
                            onDismissRequest = { clipboardExpanded = false }
                        ) {
                            clipboardOptions.forEach { secs ->
                                DropdownMenuItem(
                                    text = { Text(if (secs == 0) "Never / Disabled" else "$secs seconds") },
                                    onClick = {
                                        settingsViewModel.updateClipboardTimeout(secs)
                                        clipboardExpanded = false
                                    }
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Credentials & Cryptography",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedButton(
                onClick = { settingsViewModel.showChangeAccountPasswordDialog(true) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Change Account Password")
            }

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedButton(
                onClick = { settingsViewModel.showRotateMasterPasswordDialog(true) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Rotate Master Password (VEK Re-wrap)")
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    settingsViewModel.lock()
                    onNavigateBack()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Lock Vault Now")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    settingsViewModel.logout()
                    onLogout()
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Log Out")
            }
        }
    }
}
