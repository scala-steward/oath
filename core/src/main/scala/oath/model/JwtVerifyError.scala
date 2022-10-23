package oath.model

sealed trait JwtVerifyError {
  def error: String
}

object JwtVerifyError {

  final case class IllegalArgument(error: String) extends JwtVerifyError

  final case class AlgorithmMismatch(error: String) extends JwtVerifyError

  final case class DecodingError(fields: Seq[String], error: String) extends JwtVerifyError

  final case class VerificationError(error: String) extends JwtVerifyError

  final case class SignatureVerificationError(error: String) extends JwtVerifyError

  final case class TokenExpired(error: String) extends JwtVerifyError

  final case class UnexpectedError(error: String) extends JwtVerifyError
}
