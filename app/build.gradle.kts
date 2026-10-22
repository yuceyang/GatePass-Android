plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// Release signing material is read from environment or ~/.gradle/gradle.properties so that this
// repository never contains a keystore. Without it, `assembleRelease` still builds but produces an
// unsigned APK, which is expected for contributors.
val releaseStoreFile: String? = (findProperty("GATEPASS_STORE_FILE") as String?)
    ?: System.getenv("GATEPASS_STORE_FILE")
val releaseStorePassword: String? = (findProperty("GATEPASS_STORE_PASSWORD") as String?)
    ?: System.getenv("GATEPASS_STORE_PASSWORD")
val releaseKeyAlias: String? = (findProperty("GATEPASS_KEY_ALIAS") as String?)
    ?: System.getenv("GATEPASS_KEY_ALIAS")
val releaseKeyPassword: String? = (findProperty("GATEPASS_KEY_PASSWORD") as String?)
    ?: System.getenv("GATEPASS_KEY_PASSWORD")
val hasReleaseSigning = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
    .all { !it.isNullOrBlank() } && file(releaseStoreFile!!).exists()

android {
    namespace = "com.yuceyang.gatepassandroid"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.yuceyang.gatepassandroid"
        minSdk = 29
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.1"
        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    implementation(files("libs/hev-socks5-tunnel-2.19.1.aar"))
    testImplementation(libs.junit)
}
