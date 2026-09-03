// ITB Scala binding — thin idiomatic layer over the Java binding
// (bindings/java). The Java jar is consumed as an unmanaged jar so
// the monorepo build needs no local Maven publish step.

// ITB_JAVA_LIBS_DIR overrides the jar location (e.g. an installed
// copy of the Java binding); the default is the monorepo sibling.
val javaLibsDir = Def.setting {
  sys.env.get("ITB_JAVA_LIBS_DIR") match {
    case Some(dir) => file(dir)
    case None      => (ThisBuild / baseDirectory).value / ".." / "java" / "build" / "libs"
  }
}

// The library jar only — the eitb.jar / bench.jar tool jars embed
// duplicate copies of the library classes.
val javaBindingJars = Def.setting {
  (javaLibsDir.value * "itb-java-*.jar").classpath
}

lazy val commonSettings = Seq(
  organization := "dev.everanium",
  version := "0.3.5",
  scalaVersion := "3.6.2",
  scalacOptions ++= Seq(
    "-deprecation",
    "-feature",
    "-unchecked",
    "-Werror"
  ),
  Compile / unmanagedJars ++= javaBindingJars.value,
  // The Java binding loads the JNI shim in-process; fork so the
  // ITB_JNI_PATH env var and JVM flags reach the running code
  // instead of the sbt shell JVM.
  run / fork := true,
  Test / fork := true,
  outputStrategy := Some(StdoutOutput)
)

lazy val root = (project in file("."))
  .settings(commonSettings)
  .settings(
    name := "itb-scala",
    libraryDependencies += "org.scalameta" %% "munit" % "1.0.4" % Test
  )

lazy val bench = (project in file("bench"))
  .dependsOn(root)
  .settings(commonSettings)
  .settings(name := "itb-scala-bench")

lazy val eitb = (project in file("eitb"))
  .dependsOn(root)
  .settings(commonSettings)
  .settings(
    name := "itb-scala-eitb",
    // The hash-roster diagnostic lives in the Java binding's eitb
    // tool jar (HashRoster) — the library jar deliberately exposes
    // no primitive enumeration.
    Compile / unmanagedJars ++= (javaLibsDir.value * "eitb.jar").classpath
  )
