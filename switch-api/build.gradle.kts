// MEGATRON — switch API
//
// The HTTP service OpenSIPS calls on the call path: may this call proceed, at
// what rate, for how long — and afterwards, what did it cost.
//
// Implements contracts/authorizer.openapi.yaml. It is a separate module from
// :provisioning because the two have opposite shapes: this one is the hot
// path with a 5 ms p99 budget and must never touch PostgreSQL, while
// provisioning is a low-volume administrative API. Keeping them apart means
// the slow one cannot accidentally be given a dependency that ends up on the
// fast one's stack.
//
// It depends on :authorizer for the decision, :rating for the arithmetic, and
// :provisioning for where customers and rate tables actually live.

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
    implementation(project(":provisioning"))

    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("io.ktor:ktor-server-core:3.0.3")
    implementation("io.ktor:ktor-server-netty:3.0.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("io.ktor:ktor-server-status-pages:3.0.3")
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
    mainClass.set("net.megatron.switchapi.MainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
