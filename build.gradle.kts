import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    id("org.jetbrains.dokka") version "1.8.10"
    id("org.springframework.boot") version "3.0.6"
    id("io.spring.dependency-management") version "1.1.0"
    kotlin("jvm") version "1.8.20"
    kotlin("plugin.serialization") version "1.8.21"
    kotlin("plugin.spring") version "1.8.20"
}

group = "eu.europa.ec.euidw"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        name = "NiscyEudiwPackages"
        url = uri("https://maven.pkg.github.com/niscy-eudiw/*")
        credentials {
            username = System.getenv("GH_PKG_USER")
            password = System.getenv("GH_PKG_TOKEN")
        }
        mavenContent{
            snapshotsOnly()
        }
    }
    mavenLocal()
}

val presentationExchangeVersion = "1.0-SNAPSHOT"
val nimbusSdkVersion = "10.8"

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation("eu.europa.ec.euidw:presentation-exchange-kt:$presentationExchangeVersion")
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
