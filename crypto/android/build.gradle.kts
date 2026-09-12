plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "com.spendosaurus.crypto.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 26 // Android Keystore's AES-GCM key-wrapping is reliable from here on.
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":crypto:core"))
    implementation("com.google.crypto.tink:tink-android:1.23.0")

    testImplementation(kotlin("test"))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
