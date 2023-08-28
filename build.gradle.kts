import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    id("org.jetbrains.dokka") version "1.8.20"
    id("org.springframework.boot") version "3.1.3"
    id("io.spring.dependency-management") version "1.1.3"
    kotlin("jvm") version "1.9.0"
    kotlin("plugin.serialization") version "1.9.0"
    kotlin("plugin.spring") version "1.9.0"
    id("com.diffplug.spotless") version "6.20.0"
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        mavenContent { snapshotsOnly() }
    }
    mavenLocal()
}

val presentationExchangeVersion = "0.1.0-SNAPSHOT"
val nimbusSdkVersion = "10.13.2"

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-presentation-exchange-kt:$presentationExchangeVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
}

kotlin {
    jvmToolchain(17)
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
}

val ktlintVersion = "0.50.0"
spotless {
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}
