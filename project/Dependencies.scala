import sbt.Keys.libraryDependencies
import sbt._

object Dependencies {

  object Versions {
    val scalaTest          = "3.2.12"
    val scalaTestPlusCheck = "3.2.11.0"
    val scalacheck         = "1.17.0"
    val javaJWT            = "4.0.0"
    val config             = "1.4.2"
    val cats               = "2.8.0"
  }

  object Testing {
    val scalaTest          = "org.scalatest"     %% "scalatest"       % Versions.scalaTest          % Test
    val scalaTestPlusCheck = "org.scalatestplus" %% "scalacheck-1-15" % Versions.scalaTestPlusCheck % Test
    val scalacheck         = "org.scalacheck"    %% "scalacheck"      % Versions.scalacheck         % Test

    val all = Seq(scalaTest, scalaTestPlusCheck, scalacheck)
  }

  object Utils {
    val config = "com.typesafe"   % "config"    % Versions.config
    val cats   = "org.typelevel" %% "cats-core" % Versions.cats

    val all    = Seq(config, cats)
  }

  object Auth0 {
    val javaJWT = "com.auth0" % "java-jwt" % Versions.javaJWT

    val all = Seq(javaJWT)
  }

  lazy val core = libraryDependencies ++= Testing.all ++ Auth0.all ++ Utils.all
}
