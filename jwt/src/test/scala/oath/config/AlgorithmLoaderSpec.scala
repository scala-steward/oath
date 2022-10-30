package oath.config

import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.ConfigFactory
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}

class AlgorithmLoaderSpec extends AnyWordSpecBase with PropertyBasedTesting {

  private val AlgorithmConfigLocation = "algorithm"

  "AlgorithmLoader" should {

    "load none encryption algorithm config" in forAll { (bool: Boolean, content: Array[Byte]) =>
      val algorithmScopedConfig = ConfigFactory.load("algorithm-none").getConfig(AlgorithmConfigLocation)
      val algorithm             = AlgorithmLoader.loadAlgorithmOrThrow(algorithmScopedConfig, bool)

      algorithm.sign(content) shouldBe Algorithm.none().sign(content)
    }

//    "load RSXXX encryption algorithm with secret key" in forAll { (bool: Boolean) =>
//      val algorithmScopedConfig = ConfigFactory.load("algorithm-rsxxx").getConfig(AlgorithmConfigLocation)
//      val algorithm = AlgorithmLoader.loadAlgorithmOrThrow(algorithmScopedConfig, bool)
//
//      algorithm.getName shouldBe Algorithm.RSA256("secret").getName
//    }

    "load HSXXX encryption algorithm with secret key" in forAll { (bool: Boolean, content: Array[Byte]) =>
      val algorithmScopedConfig = ConfigFactory.load("algorithm-hsxxx").getConfig(AlgorithmConfigLocation)
      val algorithm             = AlgorithmLoader.loadAlgorithmOrThrow(algorithmScopedConfig, bool)

      algorithm.sign(content) shouldBe Algorithm.HMAC256("secret").sign(content)
    }

    "load ECXXX encryption algorithm with secret key" in {
      ConfigFactory.load("algorithm-ecxxx")
    }

    "fail to load unsupported algorithm type" in forAll { bool: Boolean =>
      val algorithmScopedConfig = ConfigFactory.load("algorithm-unsupported").getConfig(AlgorithmConfigLocation)
      the[IllegalArgumentException] thrownBy AlgorithmLoader
        .loadAlgorithmOrThrow(algorithmScopedConfig, bool) should have message "Unsupported signature algorithm: Boom"
    }
  }
}
