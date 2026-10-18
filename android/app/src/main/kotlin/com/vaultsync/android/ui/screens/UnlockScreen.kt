package com.vaultsync.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.vaultsync.android.ui.viewmodel.AuthViewModel

@Composable
fun UnlockScreen(
    authViewModel: AuthViewModel,
    username: String,
    onUnlockSuccess: () -> Unit,
    onLogout: () -> Unit
) {
    val uiState by authViewModel.uiState.collectAsState()

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Vault Locked",
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Signed in as $username",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Enter your master password to decrypt your vault items",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(32.dp))

            OutlinedTextField(
                value = uiState.masterPassword,
                onValueChange = { authViewModel.onMasterPasswordChange(it) },
                label = { Text("Vault Master Password") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                )
            )

            if (uiState.errorMessage != null) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = uiState.errorMessage ?: "",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            if (authViewModel.isBiometricUnlockAvailable()) {
                val context = androidx.compose.ui.platform.LocalContext.current
                androidx.compose.material3.OutlinedButton(
                    onClick = {
                        val activity = context as? androidx.fragment.app.FragmentActivity
                        if (activity != null) {
                            val cipher = authViewModel.getBiometricDecryptCipher()
                            if (cipher != null) {
                                val executor = androidx.core.content.ContextCompat.getMainExecutor(context)
                                val prompt = androidx.biometric.BiometricPrompt(
                                    activity,
                                    executor,
                                    object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                                        override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                                            val authenticatedCipher = result.cryptoObject?.cipher
                                            if (authenticatedCipher != null) {
                                                authViewModel.unlockWithBiometrics(authenticatedCipher, onUnlockSuccess)
                                            }
                                        }
                                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                            // Fallback to password seamlessly without blocking
                                        }
                                    }
                                )
                                val promptInfo = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                                    .setTitle("Unlock Vault")
                                    .setSubtitle("Authenticate to decrypt your vault items")
                                    .setNegativeButtonText("Use Master Password")
                                    .build()
                                prompt.authenticate(promptInfo, androidx.biometric.BiometricPrompt.CryptoObject(cipher))
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    androidx.compose.material3.Icon(
                        Icons.Filled.Lock,
                        contentDescription = null
                    )
                    androidx.compose.foundation.layout.Spacer(modifier = Modifier.width(8.dp))
                    Text("Unlock with Biometrics")
                }

                Spacer(modifier = Modifier.height(12.dp))
            }

            Button(
                onClick = { authViewModel.unlockVault(onUnlockSuccess) },
                enabled = !uiState.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.height(18.dp))
                } else {
                    Text("Unlock with Master Password")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(onClick = onLogout) {
                Text("Log Out / Switch Account")
            }
        }
    }
}
