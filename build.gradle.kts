plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.maven.publish)
    `java-test-fixtures`
}

allprojects {
    repositories {
        mavenCentral()
    }
}

sourceSets {
    create("examples") {
        compileClasspath += sourceSets.main.get().output + sourceSets.testFixtures.get().output
        runtimeClasspath += sourceSets.main.get().output + sourceSets.testFixtures.get().output
    }
}

val examplesImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.implementation.get())
    extendsFrom(configurations.testFixturesApi.get())
    extendsFrom(configurations.testImplementation.get())
    extendsFrom(configurations.testRuntimeOnly.get())
}

dependencies {
    api(libs.http4k.security.core)
    api(libs.nimbus.jose.jwt)
    compileOnly(libs.http4k.api.openapi)

    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.http4k.testing.kotest)
    testImplementation(libs.http4k.testing.approval)
    testRuntimeOnly(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)

    testFixturesApi(libs.http4k.api.openapi)

    examplesImplementation(libs.http4k.config)
    examplesImplementation(libs.http4k.server.jetty)
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