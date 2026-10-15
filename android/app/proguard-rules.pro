# ProGuard / R8 rules for VaultSync Android

# Keep BouncyCastle cryptographic algorithms
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep Kotlinx Serialization models
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.SerializationKt
-keepclassmembers class * {
    @kotlinx.serialization.SerialName <fields>;
}
-keepclasseswithmembers class * {
    companion object;
}

# Keep OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# Protect sensitive data structures from being de-obfuscated or reflected improperly
-keep class com.vaultsync.android.crypto.CryptoModels.** { *; }
-keep class com.vaultsync.android.api.ApiModels.** { *; }
-keep class com.vaultsync.android.model.VaultItem { *; }
