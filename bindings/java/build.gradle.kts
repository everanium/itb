// Build for the ITB Java binding: library jar + JNI shim + JUnit 5
// test suite + bench / eitb tool jars.
//
// The JNI shim (src/main/jni/itb3_jni.c) is compiled with the system C
// compiler and linked against libitb3.so from the repository dist
// directory, with an RPATH pointing there so the shim resolves libitb3
// at load time without LD_LIBRARY_PATH.

group = "io.github.everanium"

plugins {
    `java-library`
    `maven-publish`
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

version = "0.5.1"

// bindings/java -> <repo root>
val repoRoot: File = layout.projectDirectory.asFile.parentFile.parentFile
val distDir = File(repoRoot, "dist/linux-amd64")
val jniLib = layout.buildDirectory.file("jni/libitb3_jni.so")

sourceSets {
    create("bench") {
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
    create("eitb") {
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

val compileJni = tasks.register<Exec>("compileJni") {
    description = "Compiles the JNI shim against libitb3.so"
    val src = file("src/main/jni/itb3_jni.c")
    val header = File(distDir, "libitb3.h")
    val out = jniLib.get().asFile
    val javaHome = javaToolchains.launcherFor(java.toolchain).get()
        .metadata.installationPath.asFile
    inputs.file(src)
    inputs.file(header)
    outputs.file(out)
    doFirst { out.parentFile.mkdirs() }
    commandLine(
        "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I${javaHome}/include", "-I${javaHome}/include/linux", "-I${distDir}",
        src.absolutePath, "-o", out.absolutePath,
        "-L${distDir}", "-litb3", "-Wl,-rpath,${distDir}",
    )
}

tasks.test {
    useJUnitPlatform()
    dependsOn(compileJni)
    environment("ITB_JNI_PATH", jniLib.get().asFile.absolutePath)
    maxHeapSize = "1g"
    testLogging {
        events("passed", "failed", "skipped")
    }
}

val eitbJar = tasks.register<Jar>("eitbJar") {
    description = "Self-contained eitb CLI jar"
    archiveFileName.set("eitb.jar")
    manifest {
        attributes("Main-Class" to "io.github.everanium.itb3.eitb.Main")
    }
    from(sourceSets["eitb"].output)
    from(sourceSets.main.get().output)
}

val benchJar = tasks.register<Jar>("benchJar") {
    description = "Bench classes jar (run mains via -cp)"
    archiveFileName.set("bench.jar")
    from(sourceSets["bench"].output)
    from(sourceSets.main.get().output)
}

tasks.assemble {
    dependsOn(compileJni, eitbJar, benchJar)
}

// Maven publication metadata. No sources / javadoc jar is attached:
// the Kotlin, Groovy, Scala and Clojure bindings resolve the library
// through a `libitb3-java-*.jar` glob, and an extra classified jar in
// build/libs would match it.
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("libitb3-java")
                description.set("ITB Symmetric Cipher Construction with Ambiguity-Based Security - Java")
                url.set("https://github.com/everanium/itb")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("everanium")
                        name.set("Andrey Kuvshinov")
                        email.set("andrew@encloud.blue")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/everanium/itb.git")
                    developerConnection.set("scm:git:ssh://git@github.com/everanium/itb.git")
                    url.set("https://github.com/everanium/itb")
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/everanium/itb/issues")
                }
            }
        }
    }
}
