// Gradle build for the ITB Groovy binding — a Tier 2 thin proxy
// over the Java binding (JVM bytecode interop, no FFI hop of its
// own). The Java binding's library jar is consumed straight from the
// sibling build's output directory; libitb.so + the JNI shim are
// built and resolved by the Java layer (ITB_JNI_PATH, exported by
// the driver scripts and defaulted below for in-repo runs).

plugins {
    groovy
    `java-library`
}

group = "dev.everanium"
version = "0.3.3"

repositories {
    mavenCentral()
}

// bindings/groovy -> <repo root>
val repoRoot: File = layout.projectDirectory.asFile.parentFile.parentFile
val javaBindingDir = File(repoRoot, "bindings/java")
val jniShim = File(javaBindingDir, "build/jni/libitb_jni.so")

// The sibling Java binding's library jar (not its eitb/bench tool
// jars, which bundle duplicate copies of the main classes).
// `./build.sh` builds it before Gradle runs, so the tree is present.
val javaBindingJars = fileTree(File(javaBindingDir, "build/libs")) {
    include("itb-java-*.jar")
}

// The hash-roster diagnostic lives in the Java binding's eitb tool
// jar (HashRoster) — the library jar deliberately exposes no
// primitive enumeration. Consumed by the eitb source set only.
val javaEitbJar = fileTree(File(javaBindingDir, "build/libs")) {
    include("eitb.jar")
}

dependencies {
    api(javaBindingJars)
    implementation("org.apache.groovy:groovy:5.0.8")
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

// Bench + eitb live in flat top-level directories (fleet layout);
// each is its own source set compiled against the main output.
val bench: SourceSet by sourceSets.creating {
    groovy.srcDir("bench")
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

val eitb: SourceSet by sourceSets.creating {
    groovy.srcDir("eitb")
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations["benchImplementation"].extendsFrom(configurations["implementation"])
configurations["benchRuntimeOnly"].extendsFrom(configurations["runtimeOnly"])
configurations["eitbImplementation"].extendsFrom(configurations["implementation"])
configurations["eitbRuntimeOnly"].extendsFrom(configurations["runtimeOnly"])

dependencies {
    "eitbImplementation"(javaEitbJar)
}

/** Defaults ITB_JNI_PATH to the sibling Java build's shim when the
 * caller has not exported it. */
fun JavaForkOptions.defaultJniPath() {
    if (System.getenv("ITB_JNI_PATH") == null) {
        environment("ITB_JNI_PATH", jniShim.absolutePath)
    }
}

tasks.test {
    useJUnitPlatform()
    defaultJniPath()
    maxHeapSize = "1g"
    testLogging {
        events("passed", "failed", "skipped")
    }
}

tasks.register<JavaExec>("runBench") {
    group = "verification"
    description =
        "Runs the throughput micro-benchmarks (--args=\"message|stream|all\")."
    classpath = bench.runtimeClasspath
    mainClass = "dev.everanium.itb.groovy.bench.Main"
    defaultJniPath()
}

tasks.register<JavaExec>("runEitb") {
    group = "application"
    description = "Runs the eitb command-line demonstrator."
    classpath = eitb.runtimeClasspath
    mainClass = "dev.everanium.itb.groovy.eitb.Main"
    defaultJniPath()
}

val eitbJar = tasks.register<Jar>("eitbJar") {
    description = "Self-contained eitb CLI jar"
    archiveFileName = "eitb.jar"
    manifest {
        attributes("Main-Class" to "dev.everanium.itb.groovy.eitb.Main")
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(eitb.output)
    from(sourceSets.main.get().output)
    from(configurations["eitbRuntimeClasspath"].map { if (it.isDirectory) it else zipTree(it) })
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.assemble {
    dependsOn("benchClasses", "eitbClasses", eitbJar)
}
