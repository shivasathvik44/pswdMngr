package com.vaultsync.android.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * Parsed Autofill form representation with resolved target origin and field identifiers.
 */
data class ParsedAutofillForm(
    val target: AutofillTarget?,
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    val allFieldIds: List<AutofillId>
)

/**
 * Traverses Android AssistStructure to extract autofillable username/password fields
 * and the verified target origin (web domain or native app package).
 */
object AutofillStructureParser {

    fun parseStructure(structure: AssistStructure?): ParsedAutofillForm? {
        if (structure == null) return null
        val packageName = structure.activityComponent?.packageName ?: return null

        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        val collectedWebDomains = mutableSetOf<String>()
        val allFields = mutableListOf<AutofillId>()

        val windowCount = structure.windowNodeCount
        for (w in 0 until windowCount) {
            val windowNode = structure.getWindowNodeAt(w)
            val rootNode = windowNode.rootViewNode ?: continue
            traverseNode(rootNode) { node ->
                val autofillId = node.autofillId
                if (autofillId != null) {
                    allFields.add(autofillId)

                    // Capture web domain if provided by browser / WebView
                    val domain = node.webDomain
                    if (!domain.isNullOrBlank()) {
                        val norm = AutofillOriginMatcher.normalizeHost(domain)
                        if (norm != null) {
                            collectedWebDomains.add(norm)
                        }
                    }

                    // Classify field
                    if (isPasswordField(node)) {
                        if (passwordId == null) {
                            passwordId = autofillId
                        }
                    } else if (isUsernameField(node)) {
                        if (usernameId == null) {
                            usernameId = autofillId
                        }
                    }
                }
            }
        }

        // If multiple conflicting web domains are detected in the same form, fail closed
        if (collectedWebDomains.size > 1) {
            return null
        }

        val target = if (collectedWebDomains.isNotEmpty()) {
            AutofillTarget.Web(collectedWebDomains.first())
        } else if (AutofillOriginMatcher.isValidPackageName(packageName)) {
            AutofillTarget.App(packageName)
        } else {
            null
        }

        if (usernameId == null && passwordId == null) {
            return null
        }

        return ParsedAutofillForm(
            target = target,
            usernameId = usernameId,
            passwordId = passwordId,
            allFieldIds = allFields
        )
    }

    private fun traverseNode(node: AssistStructure.ViewNode, visitor: (AssistStructure.ViewNode) -> Unit) {
        visitor(node)
        val childCount = node.childCount
        for (i in 0 until childCount) {
            val child = node.getChildAt(i) ?: continue
            traverseNode(child, visitor)
        }
    }

    private fun isPasswordField(node: AssistStructure.ViewNode): Boolean {
        val hints = node.autofillHints
        if (hints != null) {
            for (h in hints) {
                if (h.equals(View.AUTOFILL_HINT_PASSWORD, ignoreCase = true)) {
                    return true
                }
            }
        }

        val inputType = node.inputType
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val isPasswordVariation = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        if (isPasswordVariation) return true

        val idEntry = node.idEntry?.lowercase() ?: ""
        val hint = node.hint?.toString()?.lowercase() ?: ""
        if (idEntry.contains("password") || idEntry.contains("pwd") || idEntry.contains("pass")) {
            return true
        }
        if (hint.contains("password") || hint.contains("pwd") || hint.contains("pass")) {
            return true
        }

        return false
    }

    private fun isUsernameField(node: AssistStructure.ViewNode): Boolean {
        val hints = node.autofillHints
        if (hints != null) {
            for (h in hints) {
                if (h.equals(View.AUTOFILL_HINT_USERNAME, ignoreCase = true) ||
                    h.equals(View.AUTOFILL_HINT_EMAIL_ADDRESS, ignoreCase = true) ||
                    h.equals(View.AUTOFILL_HINT_PHONE, ignoreCase = true)
                ) {
                    return true
                }
            }
        }

        val inputType = node.inputType
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val isEmailVariation = variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
        if (isEmailVariation) return true

        val idEntry = node.idEntry?.lowercase() ?: ""
        val hint = node.hint?.toString()?.lowercase() ?: ""
        if (idEntry.contains("username") || idEntry.contains("login") || idEntry.contains("email") || idEntry.contains("user")) {
            return true
        }
        if (hint.contains("username") || hint.contains("login") || hint.contains("email") || hint.contains("user")) {
            return true
        }

        return false
    }
}
