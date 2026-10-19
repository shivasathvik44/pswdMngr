package com.vaultsync.android.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.vaultsync.android.R
import com.vaultsync.android.VaultSyncApplication
import com.vaultsync.android.model.VaultItem
import com.vaultsync.android.repository.VaultRepository
import com.vaultsync.android.ui.theme.VaultSyncTheme
import kotlinx.coroutines.launch

/**
 * Dedicated secure authentication activity invoked by the Android Autofill Framework.
 *
 * Security Invariants:
 * 1. Screen Security: window is flagged with FLAG_SECURE to prevent screenshot / snapshot capture.
 * 2. Session Fencing: verifies that the current repository accountId and sessionGeneration match
 *    the snapshot when the fill request was originated.
 * 3. Explicit Authentication: secrets are NEVER returned without user authentication.
 * 4. Minimal Release: returns a single Dataset containing only the selected record's username/password.
 */
class AutofillAuthActivity : FragmentActivity() {

    companion object {
        const val EXTRA_RECORD_ID = "com.vaultsync.android.autofill.RECORD_ID"
        const val EXTRA_TARGET_TYPE = "com.vaultsync.android.autofill.TARGET_TYPE"
        const val EXTRA_TARGET_VALUE = "com.vaultsync.android.autofill.TARGET_VALUE"
        const val EXTRA_ACCOUNT_ID = "com.vaultsync.android.autofill.ACCOUNT_ID"
        const val EXTRA_SESSION_GEN = "com.vaultsync.android.autofill.SESSION_GEN"
        const val EXTRA_LOCK_GEN = "com.vaultsync.android.autofill.LOCK_GEN"
        const val EXTRA_USERNAME_ID = "com.vaultsync.android.autofill.USERNAME_ID"
        const val EXTRA_PASSWORD_ID = "com.vaultsync.android.autofill.PASSWORD_ID"
    }

    private lateinit var repository: VaultRepository

    private var targetRecordId: String? = null
    private var targetType: String? = null
    private var targetValue: String? = null
    private var expectedAccountId: String? = null
    private var expectedSessionGen: Long = 0L
    private var usernameAutofillId: AutofillId? = null
    private var passwordAutofillId: AutofillId? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshot and snapshot capture
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        val app = application as? VaultSyncApplication ?: run {
            cancelAndFinish()
            return
        }
        repository = app.repository

        // Parse extras
        targetRecordId = intent.getStringExtra(EXTRA_RECORD_ID)
        targetType = intent.getStringExtra(EXTRA_TARGET_TYPE)
        targetValue = intent.getStringExtra(EXTRA_TARGET_VALUE)
        expectedAccountId = intent.getStringExtra(EXTRA_ACCOUNT_ID)
        expectedSessionGen = intent.getLongExtra(EXTRA_SESSION_GEN, -1L)
        @Suppress("DEPRECATION")
        usernameAutofillId = intent.getParcelableExtra(EXTRA_USERNAME_ID)
        @Suppress("DEPRECATION")
        passwordAutofillId = intent.getParcelableExtra(EXTRA_PASSWORD_ID)

        // Validate session and account fencing
        if (!validateSessionState()) {
            cancelAndFinish()
            return
        }

        setContent {
            VaultSyncTheme {
                AutofillAuthContent()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!validateSessionState()) {
            cancelAndFinish()
        }
    }

    private fun validateSessionState(): Boolean {
        val currentAcc = repository.accountId
        val currentSessionGen = repository.sessionGeneration
        if (currentAcc.isBlank() || currentAcc != expectedAccountId || currentSessionGen != expectedSessionGen) {
            return false
        }
        return true
    }

    private fun cancelAndFinish() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    private fun deliverDataset(item: VaultItem) {
        val target = getAutofillTarget()
        if (target == null || !AutofillOriginMatcher.matches(target, item)) {
            cancelAndFinish()
            return
        }

        if (!validateSessionState() || !repository.sessionState.value.isUnlocked) {
            cancelAndFinish()
            return
        }

        val presentation = RemoteViews(packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_title, item.title.ifBlank { item.username })
            setTextViewText(R.id.autofill_sub_title, item.username)
        }

        val datasetBuilder = android.service.autofill.Dataset.Builder(presentation)
        val uId = usernameAutofillId
        val pId = passwordAutofillId

        var fieldAdded = false
        if (uId != null && item.username.isNotBlank()) {
            datasetBuilder.setValue(uId, AutofillValue.forText(item.username))
            fieldAdded = true
        }
        if (pId != null && item.password.isNotBlank()) {
            datasetBuilder.setValue(pId, AutofillValue.forText(item.password))
            fieldAdded = true
        }

        if (!fieldAdded) {
            cancelAndFinish()
            return
        }

        val replyIntent = Intent().apply {
            putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, datasetBuilder.build())
        }
        setResult(Activity.RESULT_OK, replyIntent)
        finish()
    }

    private fun getAutofillTarget(): AutofillTarget? {
        val tVal = targetValue ?: return null
        return when (targetType) {
            "web" -> AutofillTarget.Web(tVal)
            "app" -> AutofillTarget.App(tVal)
            else -> null
        }
    }

    private fun triggerBiometricPrompt(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val accId = repository.accountId
        if (accId.isBlank() || !repository.biometricKeyManager.isBiometricEnabled(accId)) {
            onError("Biometric authentication not enabled")
            return
        }

        val cipher = try {
            repository.biometricKeyManager.initDecryptCipher(accId)
        } catch (e: Exception) {
            onError(e.message ?: "Failed to initialize biometric cipher")
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authCipher = result.cryptoObject?.cipher
                    if (authCipher != null) {
                        try {
                            val vek = repository.biometricKeyManager.unwrapVek(authCipher, accId)
                            try {
                                kotlinx.coroutines.runBlocking {
                                    repository.unlockWithVek(vek, expectedAccountId, expectedSessionGen)
                                }
                                onSuccess()
                            } finally {
                                com.vaultsync.android.crypto.VaultCrypto.clearBytes(vek)
                            }
                        } catch (e: Exception) {
                            onError("Biometric unlock failed: ${e.message}")
                        }
                    } else {
                        onError("Biometric cipher authorization missing")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autofill Authentication")
            .setSubtitle("Confirm your biometric to autofill credentials")
            .setNegativeButtonText("Use Master Password")
            .build()

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    @Composable
    private fun AutofillAuthContent() {
        val scope = rememberCoroutineScope()
        var isUnlocked by remember { mutableStateOf(repository.sessionState.value.isUnlocked) }
        var masterPasswordInput by remember { mutableStateOf("") }
        var errorMessage by remember { mutableStateOf<String?>(null) }
        var isLoading by remember { mutableStateOf(false) }

        val target = remember { getAutofillTarget() }
        val targetLabel = remember {
            when (target) {
                is AutofillTarget.Web -> target.host
                is AutofillTarget.App -> target.packageName
                null -> "Application"
            }
        }

        // Unlocked vault flow: Require explicit user authorization before release
        if (isUnlocked) {
            val recId = targetRecordId
            if (recId != null) {
                val item = repository.getItem(recId)
                if (item == null || target == null || !AutofillOriginMatcher.matches(target, item)) {
                    cancelAndFinish()
                    return
                }

                // Explicit authorization screen for selected record
                Scaffold { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Authorize Autofill",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Confirm filling credentials into $targetLabel",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(item.title.ifBlank { item.username }, fontWeight = FontWeight.Bold)
                                Text(item.username, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                        if (errorMessage != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(errorMessage ?: "", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(modifier = Modifier.height(24.dp))
                        if (repository.isBiometricUnlockAvailable()) {
                            OutlinedButton(
                                onClick = {
                                    triggerBiometricPrompt(
                                        onSuccess = { deliverDataset(item) },
                                        onError = { errorMessage = it }
                                    )
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Confirm with Biometrics")
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                        Button(
                            onClick = { deliverDataset(item) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Confirm & Fill")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = { cancelAndFinish() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Cancel")
                        }
                    }
                }
                return
            }

            // If recId was null (unlocked from response-level prompt), find matching items
            val matchingItems = remember {
                if (target != null) {
                    repository.getItems().filter { AutofillOriginMatcher.matches(target, it) }
                } else emptyList()
            }

            if (matchingItems.size == 1) {
                val singleItem = matchingItems.first()
                Scaffold { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Authorize Autofill",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Confirm filling credentials into $targetLabel",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(singleItem.title.ifBlank { singleItem.username }, fontWeight = FontWeight.Bold)
                                Text(singleItem.username, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                        Spacer(modifier = Modifier.height(24.dp))
                        Button(
                            onClick = { deliverDataset(singleItem) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Confirm & Fill")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = { cancelAndFinish() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Cancel")
                        }
                    }
                }
                return
            }

            // Multiple matching items: display chooser
            Scaffold { padding ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(16.dp)
                ) {
                    Text(
                        text = "Select Account for $targetLabel",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (matchingItems.isEmpty()) {
                        Text("No saved credentials match $targetLabel")
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = { cancelAndFinish() }) {
                            Text("Cancel")
                        }
                    } else {
                        LazyColumn(modifier = Modifier.weight(1f)) {
                            items(matchingItems) { item ->
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp)
                                        .clickable { deliverDataset(item) },
                                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                                ) {
                                    Column(modifier = Modifier.padding(12.dp)) {
                                        Text(item.title.ifBlank { item.username }, fontWeight = FontWeight.SemiBold)
                                        Text(item.username, style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(onClick = { cancelAndFinish() }, modifier = Modifier.fillMaxWidth()) {
                            Text("Cancel")
                        }
                    }
                }
            }
            return
        }

        // Vault is locked: prompt for authentication
        Scaffold { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "VaultSync Autofill",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Authenticate to fill credentials into $targetLabel",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(24.dp))

                OutlinedTextField(
                    value = masterPasswordInput,
                    onValueChange = { masterPasswordInput = it; errorMessage = null },
                    label = { Text("Vault Master Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                    modifier = Modifier.fillMaxWidth()
                )

                if (errorMessage != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(errorMessage ?: "", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }

                Spacer(modifier = Modifier.height(16.dp))

                if (repository.isBiometricUnlockAvailable()) {
                    OutlinedButton(
                        onClick = {
                            triggerBiometricPrompt(
                                onSuccess = { isUnlocked = true },
                                onError = { errorMessage = it }
                            )
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Unlock with Biometrics")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                }

                Button(
                    onClick = {
                        if (masterPasswordInput.isBlank()) {
                            errorMessage = "Master password required"
                            return@Button
                        }
                        isLoading = true
                        scope.launch {
                            try {
                                repository.unlockVault(masterPasswordInput)
                                isUnlocked = true
                            } catch (e: Exception) {
                                errorMessage = "Unlock failed: ${e.message}"
                            } finally {
                                isLoading = false
                            }
                        }
                    },
                    enabled = !isLoading,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.height(18.dp))
                    } else {
                        Text("Unlock & Fill")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                TextButton(onClick = { cancelAndFinish() }) {
                    Text("Cancel")
                }
            }
        }
    }
}
