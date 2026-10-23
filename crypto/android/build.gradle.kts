plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "com.spendosaurus.crypto.android"
    compileSdk = 36

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
    // tink-android below is a superset of plain tink (Android-optimized, same
    // classes), so crypto:core's own plain "tink" dependency is excluded here
    // to avoid shipping both -- they duplicate every class name and the
    // Android build's class-merge step correctly refuses to guess which one
    // wins. crypto:core keeps depending on plain "tink" itself so it stays
    // pure-JVM and testable with `./gradlew :crypto:core:test` outside Android.
    api(project(":crypto:core")) {
        exclude(group = "com.google.crypto.tink", module = "tink")
    }
    implementation("com.google.crypto.tink:tink-android:1.24.0")

    testImplementation(kotlin("test"))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
