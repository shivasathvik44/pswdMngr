package com.vaultsync.android.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.vaultsync.android.R
import com.vaultsync.android.VaultSyncApplication
import com.vaultsync.android.repository.VaultRepository

/**
 * Android Autofill Service implementing secure, origin-bound, authenticated credential filling.
 *
 * Security Invariants:
 * 1. Explicit Opt-In: Requires isAutofillEnabled preference to be true; otherwise returns null.
 * 2. Origin-Bound: Strictly validates web domain or application package via [AutofillOriginMatcher].
 * 3. Authentication Required: Credentials are NEVER returned in cleartext upon fill request.
 *    Every fill dataset or response requires user authentication through [AutofillAuthActivity].
 * 4. Stale-Session Resistance: Session and lock generation tokens are stamped onto pending intents.
 * 5. Minimal Release: Never releases arbitrary vault items.
 */
class VaultAutofillService : AutofillService() {

    private val repository: VaultRepository?
        get() = (applicationContext as? VaultSyncApplication)?.repository

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        if (cancellationSignal.isCanceled) return

        val repo = repository ?: run {
            callback.onSuccess(null)
            return
        }

        // 1. Opt-in verification
        if (!repo.isAutofillEnabled()) {
            callback.onSuccess(null)
            return
        }

        // 2. Parse AssistStructure
        val structure = request.fillContexts.lastOrNull()?.structure
        val form = AutofillStructureParser.parseStructure(structure)
        if (form == null || form.target == null) {
            callback.onSuccess(null)
            return
        }

        val response = buildFillResponse(this, form, repo)
        callback.onSuccess(response)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Safe Save Flow: Deferred to maintain security integrity.
        // Plaintext credential capture outside confirmed user dialogue is prohibited.
        callback.onSuccess()
    }

    companion object {
        /**
         * Pure construction of FillResponse for a parsed form and current vault state.
         * Returns null if autofill is disabled, unauthenticated, form target is missing,
         * or no matching credentials exist.
         */
        fun buildFillResponse(
            context: Context,
            form: ParsedAutofillForm,
            repo: VaultRepository
        ): FillResponse? {
            if (!repo.isAutofillEnabled()) return null
            val target = form.target ?: return null

            val accountId = repo.accountId
            val sessionGen = repo.sessionGeneration
            val lockGen = repo.lockGeneration
            val isUnlocked = repo.sessionState.value.isUnlocked

            if (accountId.isBlank() || !repo.sessionState.value.isAuthenticated) {
                return null
            }

            val targetTypeStr = when (target) {
                is AutofillTarget.Web -> "web"
                is AutofillTarget.App -> "app"
            }
            val targetValueStr = when (target) {
                is AutofillTarget.Web -> target.host
                is AutofillTarget.App -> target.packageName
            }

            return if (isUnlocked) {
                val matchingItems = repo.getItems().filter { AutofillOriginMatcher.matches(target, it) }
                if (matchingItems.isEmpty()) return null

                val responseBuilder = FillResponse.Builder()

                for (item in matchingItems) {
                    val authIntent = Intent(context, AutofillAuthActivity::class.java).apply {
                        putExtra(AutofillAuthActivity.EXTRA_RECORD_ID, item.id)
                        putExtra(AutofillAuthActivity.EXTRA_TARGET_TYPE, targetTypeStr)
                        putExtra(AutofillAuthActivity.EXTRA_TARGET_VALUE, targetValueStr)
                        putExtra(AutofillAuthActivity.EXTRA_ACCOUNT_ID, accountId)
                        putExtra(AutofillAuthActivity.EXTRA_SESSION_GEN, sessionGen)
                        putExtra(AutofillAuthActivity.EXTRA_LOCK_GEN, lockGen)
                        putExtra(AutofillAuthActivity.EXTRA_USERNAME_ID, form.usernameId)
                        putExtra(AutofillAuthActivity.EXTRA_PASSWORD_ID, form.passwordId)
                    }

                    val pendingIntent = PendingIntent.getActivity(
                        context,
                        item.id.hashCode(),
                        authIntent,
                        PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE
                    )

                    val presentation = RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
                        setTextViewText(R.id.autofill_title, item.title.ifBlank { item.username })
                        setTextViewText(R.id.autofill_sub_title, item.username)
                    }

                    val datasetBuilder = Dataset.Builder(presentation)
                    datasetBuilder.setAuthentication(pendingIntent.intentSender)

                    // Pass null values so credentials remain completely concealed until user authenticates
                    if (form.usernameId != null) {
                        datasetBuilder.setValue(form.usernameId, null)
                    }
                    if (form.passwordId != null) {
                        datasetBuilder.setValue(form.passwordId, null)
                    }

                    responseBuilder.addDataset(datasetBuilder.build())
                }

                responseBuilder.build()
            } else {
                val authIntent = Intent(context, AutofillAuthActivity::class.java).apply {
                    putExtra(AutofillAuthActivity.EXTRA_TARGET_TYPE, targetTypeStr)
                    putExtra(AutofillAuthActivity.EXTRA_TARGET_VALUE, targetValueStr)
                    putExtra(AutofillAuthActivity.EXTRA_ACCOUNT_ID, accountId)
                    putExtra(AutofillAuthActivity.EXTRA_SESSION_GEN, sessionGen)
                    putExtra(AutofillAuthActivity.EXTRA_LOCK_GEN, lockGen)
                    putExtra(AutofillAuthActivity.EXTRA_USERNAME_ID, form.usernameId)
                    putExtra(AutofillAuthActivity.EXTRA_PASSWORD_ID, form.passwordId)
                }

                val pendingIntent = PendingIntent.getActivity(
                    context,
                    target.hashCode(),
                    authIntent,
                    PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                val presentation = RemoteViews(context.packageName, R.layout.autofill_auth_prompt)
                val fieldsToAuth = listOfNotNull(form.usernameId, form.passwordId).toTypedArray()

                if (fieldsToAuth.isEmpty()) return null

                FillResponse.Builder()
                    .setAuthentication(fieldsToAuth, pendingIntent.intentSender, presentation)
                    .build()
            }
        }
    }
}
