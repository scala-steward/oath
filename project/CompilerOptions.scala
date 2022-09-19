import sbt.Keys._
import sbt._

object CompilerOptions {

  val inCompile = Compile / scalacOptions ++= Seq(
    "-deprecation",           // Emit warning and location for usages of deprecated APIs.
    "-encoding",              // ->
    "utf-8",                  // Specify character encoding used by source files.
    "-explaintypes",          // Explain type errors in more detail.
    "-feature",               // Emit warning and location for usages of features that should be imported explicitly.
    "-language:existentials", // Existential types (besides wildcard types) can be written and inferred
    "-language:experimental.macros", // Allow macro definition (besides implementation and application)
    "-language:higherKinds",         // Allow higher-kinded types
    "-language:implicitConversions", // Allow definition of implicit functions called views
    "-language:postfixOps",          // Allow postfix operator notation, such as 1 to 10 toList (not recommended)
    "-target:jvm-1.8",               // Target platform for object files
    "-unchecked",                    // Enable additional warnings where generated code depends on assumptions.
    "-Xcheckinit",                   // Wrap field accessors to throw an exception on uninitialized access.
    "-Xlint",                        // Enable recommended warnings
    "-Ywarn-dead-code",              // Warn when dead code is identified.
    "-Ywarn-extra-implicit",         // Warn when more than one implicit parameter section is defined.
    "-Ywarn-numeric-widen",          // Warn when numerics are widened.
    "-Wunused",                      // Enable unused warnings
    "-Xlint:adapted-args",           // Warn if an argument list is modified to match the receiver.
    "-Xlint:-byname-implicit" // Suppress warning block result was adapted via implicit conversion (method apply) taking a by-name parameter https://github.com/scala/bug/issues/12072#issuecomment-884514638
  )

  val inTest =
    Test / scalacOptions --= Seq("-Ywarn-dead-code", "-Ywarn-numeric-widen", "-Ywarn-value-discard")
}
