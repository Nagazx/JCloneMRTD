plugins {
    kotlin("jvm") version "1.8.20"
    id("org.jetbrains.compose") version "1.4.0"
}

group = "org.jclonemrtd"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    google()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(compose.desktop.currentOs)

}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

compose.desktop {
    application {
        mainClass = "MainKt"
    }
}