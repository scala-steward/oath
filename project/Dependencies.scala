import sbt.Keys.libraryDependencies
import sbt._

object Dependencies {

  object Versions {
    val scalaTest          = "3.2.14"
    val scalaTestPlusCheck = "3.2.11.0"
    val scalacheck         = "1.17.0"
    val javaJWT            = "4.0.0"
    val config             = "1.4.2"
    val cats               = "2.8.0"
    val bcprov             = "1.70"
    val logbackClassic     = "1.4.3"
    val scalaLogging       = "3.9.5"
    val circe              = "0.14.3"
  }

  object Circe {
    val core    = "io.circe" %% "circe-core"    % Versions.circe
    val generic = "io.circe" %% "circe-generic" % Versions.circe
    val parser  = "io.circe" %% "circe-parser"  % Versions.circe

    val all = Seq(core, generic, parser)
  }

  object Testing {
    val scalaTest          = "org.scalatest"     %% "scalatest"       % Versions.scalaTest          % Test
    val scalaTestPlusCheck = "org.scalatestplus" %% "scalacheck-1-15" % Versions.scalaTestPlusCheck % Test
    val scalacheck         = "org.scalacheck"    %% "scalacheck"      % Versions.scalacheck         % Test

    val all = Seq(scalaTest, scalaTestPlusCheck, scalacheck)
  }

  object Utils {
    val config         = "com.typesafe"                % "config"          % Versions.config
    val cats           = "org.typelevel"              %% "cats-core"       % Versions.cats
    val bcprov         = "org.bouncycastle"            % "bcprov-jdk15on"  % Versions.bcprov
    val logbackClassic = "ch.qos.logback"              % "logback-classic" % Versions.logbackClassic
    val scalaLogging   = "com.typesafe.scala-logging" %% "scala-logging"   % Versions.scalaLogging

    val all = Seq(config, cats, bcprov, logbackClassic, scalaLogging)
  }

  object Auth0 {
    val javaJWT = "com.auth0" % "java-jwt" % Versions.javaJWT

    val all = Seq(javaJWT)
  }

  lazy val core = libraryDependencies ++= Testing.all ++ Auth0.all ++ Utils.all ++ Circe.all.map(_ % Test)
}
