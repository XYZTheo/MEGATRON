// MEGATRON — provisioning service
//
// The HTTP surface of contracts/provisioning.openapi.yaml: customers, logins,
// balance, caller ID, plans, trunks. The Telegram bot is its first client and
// the admin console will be its second (docs/PRODUCT.md).
//
// Storage is behind an interface with an in-memory implementation, so the
// service RUNS and is testable end to end today, on a machine with no
// PostgreSQL and no Linux. Swapping in the real store when the VPS exists is
// then a single implementation, not a rewrite.

plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":rating"))
    implementation(project(":authorizer"))

    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    implementation("io.ktor:ktor-server-core:3.0.3")
    implementation("io.ktor:ktor-server-netty:3.0.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("io.ktor:ktor-server-status-pages:3.0.3")
    implementation("io.ktor:ktor-server-auth:3.0.3")
    implementation("io.ktor:ktor-server-call-logging:3.0.3")
    // slf4j-simple rather than Logback: Logback is dual-licensed
    // EPL-1.0/LGPL-2.1 and would leave MEGATRON carrying a licence election
    // in every conversation with an operator we sell to. See the note in
    // ci/approved-dependencies.json before changing this.
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.0.21")
    testImplementation("io.ktor:ktor-server-test-host:3.0.3")
    testImplementation("io.ktor:ktor-client-content-negotiation:3.0.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.3")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("net.megatron.provisioning.MainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
