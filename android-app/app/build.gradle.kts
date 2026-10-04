plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

android {
    namespace = "io.github.infarctus.nodauth"
    compileSdk = 36
    defaultConfig {
        applicationId = "io.github.infarctus.nodauth"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += "arm64-v8a" }
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    // Preserve dependency license texts when more than one library supplies them.
    packaging { resources.merges += setOf("META-INF/AL2.0", "META-INF/LGPL2.1") }
    sourceSets.getByName("main") {
        assets.srcDir(layout.buildDirectory.dir("generated/legal-assets"))
    }
}

val legalAssets by tasks.registering(Sync::class) {
    from(rootProject.file("..")) {
        include("LICENSE", "THIRD_PARTY_NOTICES.md", "PRIVACY.md", "licenses/**")
    }
    into(layout.buildDirectory.dir("generated/legal-assets/legal"))
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(legalAssets)
}

val sharedPython by tasks.registering(Sync::class) {
    from(rootProject.file("../app")) {
        include("__init__.py", "state.py", "state_bundle.py", "app_identity.py", "activation.py", "approval.py",
                "registration.py", "registration_runtime.py", "fcm.py", "fcm_lifecycle.py",
                "mcs.py", "entra_registration.py", "extract_apk_config.py")
    }
    into(layout.buildDirectory.dir("shared-python/app"))
}
chaquopy {
    defaultConfig {
        version = "3.13"
        val pythonCommand = providers.gradleProperty("buildPython").orNull
        if (pythonCommand != null) buildPython(pythonCommand)
        pip {
            options("--find-links", rootProject.file(".toolchain/wheels").absolutePath)
            install("curl-cffi==0.16.3")
            install("certifi==2026.7.22")
            install("cffi==2.0.0")
            install("pycparser==3.0")
        }
        extractPackages("curl_cffi", "curl_cffi.libs")
    }
    sourceSets.getByName("main") { srcDir(layout.buildDirectory.dir("shared-python")) }
}
val mobileCffi by tasks.registering(Exec::class) {
    workingDir(rootProject.projectDir)
    commandLine("python3", "tools/build_cffi.py")
    inputs.file(rootProject.file("tools/build_cffi.py"))
    outputs.file(rootProject.file(".toolchain/wheels/cffi-2.0.0-cp313-cp313-android_24_arm64_v8a.whl"))
}
tasks.matching { it.name.startsWith("install") && it.name.endsWith("PythonRequirements") }.configureEach {
    dependsOn(mobileCffi)
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("PythonSources") }.configureEach {
    dependsOn(sharedPython)
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.11.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("junit:junit:4.13.2")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
