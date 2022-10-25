package oath.testkit

import org.scalactic.anyvals.PosInt
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

trait PropertyBasedTesting extends ScalaCheckPropertyChecks with Arbitraries {
  val minSuccessful = PosInt(1)

  implicit override val generatorDrivenConfig: PropertyCheckConfiguration = PropertyCheckConfiguration(minSuccessful)
}
