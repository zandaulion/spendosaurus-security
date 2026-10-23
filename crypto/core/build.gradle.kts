plugins {
    kotlin("jvm")
    kotlin("plugin.serialization") version "2.0.21"
}

group = "com.spendosaurus"
version = "0.1.0"

dependencies {
    // Tink: Google's audited, widely-reviewed crypto API. We use it instead of
    // hand-rolled AES-GCM/X25519 so the primitives themselves are not part of
    // what a reviewer has to trust us on -- only the composition is ours.
    implementation("com.google.crypto.tink:tink:1.23.0")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}
