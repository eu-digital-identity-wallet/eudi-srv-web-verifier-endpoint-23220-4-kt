import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    base
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.sonarqube)
    alias(libs.plugins.dependencycheck)
    jacoco
}

repositories {
    mavenCentral()
    mavenLocal()
    maven {
        url = uri("https://maven.waltid.dev/releases")
        mavenContent {
        }
    }
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
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation(libs.bouncy.castle)
    implementation(libs.arrow.core)
    implementation(libs.arrow.fx.coroutines)
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.webjars:webjars-locator-core")
    implementation(libs.swagger.ui)
    implementation(libs.waltid.mdoc.credentials) {
        because("To verify CBOR credentials")
    }
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1") {
        because("required by walt.id")
    }
    implementation("com.augustcellars.cose:cose-java:1.1.0") {
        because("required by walt.id")
    }
    implementation(libs.sd.jwt)
    implementation(libs.ktor.client.java) {
        because("ktor client engine to use (required by SdJwtVcVerifier)")
    }

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
}

java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
}

kotlin {

    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get()))
    }

    compilerOptions {
        apiVersion.set(KotlinVersion.KOTLIN_2_0)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.test {
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)

    reports {
        xml.required = true
        csv.required = true
        html.required = true
    }
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
    publish.set(false)
    // get the BP_OCI_* from env, for https://github.com/paketo-buildpacks/image-labels
    // get the BP_JVM_* from env, jlink optimisation
    environment.set(System.getenv())
    val env = environment.get()
    docker {
        publishRegistry {
            env["REGISTRY_URL"]?.let { url = it }
            env["REGISTRY_USERNAME"]?.let { username = it }
            env["REGISTRY_PASSWORD"]?.let { password = it }
        }
        env["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

spotless {
    val ktlintVersion = libs.versions.ktlintVersion.get()
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

val nvdApiKey: String? = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString()
val dependencyCheckExtension = extensions.findByType(DependencyCheckExtension::class.java)
dependencyCheckExtension?.apply {
    formats = mutableListOf("XML", "HTML")
    nvd.apiKey = nvdApiKey ?: ""
}
