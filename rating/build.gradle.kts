// MEGATRON — rating engine
//
// Deliberately dependency-free beyond the Kotlin stdlib and a test runner.
// This module computes money. Every dependency added here is something that
// could get a call priced wrong, and there is nothing in prefix matching or
// integer arithmetic that needs a library.
//
// Every dependency must also appear in ci/approved-dependencies.json with a
// licence, or the LICENCE policy gate fails the build — MEGATRON is
// proprietary and cannot link GPL/AGPL/LGPL code.

plugins {
    kotlin("jvm") version "2.0.21"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.0.21")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.3")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
