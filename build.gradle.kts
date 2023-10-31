import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import kotlin.jvm.optionals.getOrNull

plugins {
    base
    alias(libs.plugins.dokka)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        mavenContent { snapshotsOnly() }
    }
    mavenLocal()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation(libs.presentation.exchange)
    implementation(libs.nimbusds.oauth2.oidc.sdk)
    implementation(libs.spring.boot.security)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
}

java {
    val javaVersion = getVersionFromCatalog("java")
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
}

kotlin {

    jvmToolchain {
        val javaVersion = getVersionFromCatalog("java")
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
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
    imageName.set("${project.name}")
    publish.set(false)
    docker {
        publishRegistry {
            url = System.getenv("REGISTRY_URL")
            username = System.getenv("REGISTRY_USERNAME")
            password = System.getenv("REGISTRY_PASSWORD")
        }
    }
    // get the BP_OCI_* from env, for https://github.com/paketo-buildpacks/image-labels
    // get the BP_JVM_* from env, jlink optimisation
    environment.set(System.getenv())
}

spotless {
    val ktlintVersion = getVersionFromCatalog("ktlintVersion")
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

fun getVersionFromCatalog(lookup: String): String {
    val versionCatalog: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
    return versionCatalog
        .findVersion(lookup)
        .getOrNull()
        ?.requiredVersion
        ?: throw GradleException("Version '$lookup' is not specified in the version catalog")
}
