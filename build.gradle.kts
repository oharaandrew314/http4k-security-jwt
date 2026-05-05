plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.maven.publish)
}

allprojects {
    repositories {
        mavenCentral()
    }
}

dependencies {
    api(libs.http4k.security.core)

    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.http4k.testing.kotest)

    testRuntimeOnly(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}

tasks.compileKotlin {
    compilerOptions {
        allWarningsAsErrors = true
    }
}