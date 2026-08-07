// MEGATRON — authorizer
//
// The money decision on the call path: may this call proceed, at what rate,
// and for how long. Depends on :rating and nothing else.
//
// Still deliberately I/O-free. The real service will put HTTP and Redis
// around this, but the DECISION has to be testable without either — it is the
// thing that says yes or no to revenue.

plugins {
    kotlin("jvm") version "2.0.21"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":rating"))
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
    testLogging { events("passed", "failed", "skipped") }
}
