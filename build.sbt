ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.10"

ThisBuild / scalafixDependencies += "com.github.liancheng" %% "organize-imports" % "0.6.0"
Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = Projects
  .createModule("oath", ".")
  .settings(Aliases.all)
  .aggregate(modules: _*)

lazy val jwt = Projects
  .createModule("jwt")
  .settings(Dependencies.core)

lazy val csrf = Projects
  .createModule("csrf")
  .settings(Dependencies.core)

lazy val modules: Seq[ProjectReference] = Seq(
  jwt,
  csrf
)
