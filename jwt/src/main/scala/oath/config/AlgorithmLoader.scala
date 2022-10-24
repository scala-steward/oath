package oath.config

import java.io.{File, FileReader}
import java.security.interfaces.{ECKey, RSAKey}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}

import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.Config
import org.bouncycastle.util.io.pem.PemReader

import scala.util.Using

import scala.util.chaining.scalaUtilChainingOps

object AlgorithmLoader {

  private val SignKeyConfigObject   = "sign-key"
  private val VerifyKeyConfigObject = "verify-key"

  private val SecretKeyConfigValue         = "secret-key"
  private val PrivateKeyPemPathConfigValue = "private-key-pem-path"
  private val PublicKeyPemPathConfigValue  = "public-key-pem-path"

  private val RSAKeyFactoryInstance = "RSA"
  private val ECKeyFactoryInstance  = "EC"

  private def loadSecretKeyOrThrow(algorithmScoped: Config, forIssuing: Boolean): String =
    if (forIssuing) algorithmScoped.getConfig(SignKeyConfigObject).getString(SecretKeyConfigValue)
    else algorithmScoped.getConfig(VerifyKeyConfigObject).getString(SecretKeyConfigValue)

  private def loadRSAKeyOrThrow(algorithmScoped: Config, forIssuing: Boolean): RSAKey = {
    val RSAKeyFactory = KeyFactory.getInstance(RSAKeyFactoryInstance)
    if (forIssuing) loadPrivateKey(algorithmScoped, RSAKeyFactory).asInstanceOf[RSAKey]
    else loadPublicKey(algorithmScoped, RSAKeyFactory).asInstanceOf[RSAKey]
  }

  private def loadECKeyOrThrow(algorithmScoped: Config, forIssuing: Boolean): ECKey = {
    val ECKeyFactory = KeyFactory.getInstance(ECKeyFactoryInstance)
    if (forIssuing) loadPrivateKey(algorithmScoped, ECKeyFactory).asInstanceOf[ECKey]
    else loadPublicKey(algorithmScoped, ECKeyFactory).asInstanceOf[ECKey]
  }

  private def loadPublicKey(algorithmScoped: Config, keyFactory: KeyFactory): Either[String, PublicKey] =
    algorithmScoped
      .getConfig(VerifyKeyConfigObject)
      .getString(PublicKeyPemPathConfigValue)
      .pipe(privateKeyPemPath =>
        Using(new FileReader(new File(privateKeyPemPath))) { reader =>
          new PemReader(reader)
            .pipe(_.readPemObject().getContent)
            .pipe(new X509EncodedKeySpec(_))
            .pipe(keyFactory.generatePublic)
        }.toEither.left
          .map(error => s"Failed to load public key pem file: ${error.getMessage}"))

  private def loadPrivateKey(signatureScoped: Config, keyFactory: KeyFactory): Either[String, PrivateKey] =
    signatureScoped
      .getConfig(SignKeyConfigObject)
      .getString(PrivateKeyPemPathConfigValue)
      .pipe(privateKeyPemPath =>
        Using(new FileReader(new File(privateKeyPemPath))) { reader =>
          new PemReader(reader)
            .pipe(_.readPemObject().getContent)
            .pipe(new PKCS8EncodedKeySpec(_))
            .pipe(keyFactory.generatePrivate)
        }.toEither.left
          .map(error => s"Failed to load private key pem file: ${error.getMessage}"))

  def loadAlgorithmOrThrow(algorithmScoped: Config, forIssuing: Boolean): Algorithm =
    algorithmScoped.getString("name").trim.toUpperCase match {
      case "HS256" =>
        loadSecretKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.HMAC256)
      case "HS384" =>
        loadSecretKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.HMAC384)
      case "HS512" =>
        loadSecretKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.HMAC512)
      case "RS256" =>
        loadRSAKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.RSA256)
      case "RS384" =>
        loadRSAKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.RSA256)
      case "RS512" =>
        loadRSAKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.RSA256)
      case "ES256" =>
        loadECKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.ECDSA256)
      case "ES384" =>
        loadECKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.ECDSA384)
      case "ES512" =>
        loadECKeyOrThrow(algorithmScoped, forIssuing).pipe(Algorithm.ECDSA512)
      case "NONE" => Algorithm.none()
      case other =>
        throw new IllegalArgumentException(s"Unsupported signature algorithm: $other")
    }
}
