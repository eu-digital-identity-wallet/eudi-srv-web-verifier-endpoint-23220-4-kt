import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    id("org.jetbrains.dokka") version "1.8.10"
    id("org.springframework.boot") version "3.1.0"
    id("io.spring.dependency-management") version "1.1.0"
    kotlin("jvm") version "1.8.21"
    kotlin("plugin.serialization") version "1.8.21"
    kotlin("plugin.spring") version "1.8.21"
    id("com.diffplug.spotless") version "6.19.0"
}

repositories {
    mavenCentral()
    maven {
        name = "EUDIWalletSnapshots"
        val dependenciesRepoUrl = System.getenv("DEP_MVN_REPO") ?: "https://maven.pkg.github.com/eu-digital-identity-wallet/*"
        url = uri(dependenciesRepoUrl)
        credentials {
            username = System.getenv("GH_PKG_USER")
            password = System.getenv("GH_PKG_TOKEN")
        }
        mavenContent {
            snapshotsOnly()
        }
    }
    mavenLocal()
}

val presentationExchangeVersion = "0.1.0-SNAPSHOT"
val nimbusSdkVersion = "10.9.1"

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

tasks.withType<Test> {
    useJUnitPlatform()
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
}

val ktlintVersion = "0.49.1"
spotless {
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("LICENSE-HEADER.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}
