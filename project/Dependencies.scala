import sbt.Keys.libraryDependencies
import sbt._

object Dependencies {

  object Versions {
    val scalaTest          = "3.2.12"
    val scalaTestPlusCheck = "3.2.11.0"
    val scalacheck         = "1.16.0"
    val catsCore           = "2.8.0"
  }

  object Testing {
    val scalaTest          = "org.scalatest"     %% "scalatest"       % Versions.scalaTest          % Test
    val scalaTestPlusCheck = "org.scalatestplus" %% "scalacheck-1-15" % Versions.scalaTestPlusCheck % Test
    val scalacheck         = "org.scalacheck"    %% "scalacheck"      % Versions.scalacheck         % Test

    val all = Seq(scalaTest, scalaTestPlusCheck, scalacheck)
  }

  lazy val core = libraryDependencies ++= Testing.all
}
