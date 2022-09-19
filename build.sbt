ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.8"

ThisBuild / scalafixDependencies += "com.github.liancheng" %% "organize-imports" % "0.6.0"
Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = Projects
  .createModule("oauth", ".")
  .settings(Aliases.all)
  .aggregate(modules: _*)

lazy val core = Projects.createModule("core").settings(Dependencies.core)

lazy val modules: Seq[ProjectReference] = Seq(
  core
)
