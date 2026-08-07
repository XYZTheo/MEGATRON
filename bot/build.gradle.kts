// MEGATRON — Telegram bot
//
// The interface the business is operated through (docs/PRODUCT.md, issue #20).
// There is no web panel in the owner's workflow: this generates logins, moves
// balance, and lets customers top up and set their own caller ID.
//
// It is a CLIENT of the provisioning API, not a second implementation of it.
// The command engine is separated from the Telegram transport so the whole of
// the business behaviour is testable without a bot token, a network, or
// Telegram being up.

plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":provisioning"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.0.21")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.3")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("net.megatron.bot.MainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
