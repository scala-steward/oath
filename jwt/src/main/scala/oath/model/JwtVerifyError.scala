package oath.model

sealed trait JwtVerifyError {
  def error: String
}

object JwtVerifyError {

  final case class IllegalArgument(error: String) extends JwtVerifyError

  final case class AlgorithmMismatch(error: String) extends JwtVerifyError

  final case class DecodingError(fields: Seq[String], message: String) extends JwtVerifyError {
    val error = s"$message with fields: [${fields.mkString(",")}]"
  }

  final case class DecodingErrors(headerDecodingError: Option[DecodingError],
                                  payloadDecodingError: Option[DecodingError]
  ) extends JwtVerifyError {
    val headerMessage  = headerDecodingError.map(decodingError => s"\nheader decoding error: ${decodingError.error}")
    val payloadMessage = payloadDecodingError.map(decodingError => s"\npayload decoding error: ${decodingError.error}")
    val error =
      s"JWT Failed to decode both parts: ${headerMessage.getOrElse("")} ${payloadMessage.getOrElse("")}"
  }

  final case class VerificationError(error: String) extends JwtVerifyError

  final case class SignatureVerificationError(error: String) extends JwtVerifyError

  final case class TokenExpired(error: String) extends JwtVerifyError

  final case class UnexpectedError(error: String) extends JwtVerifyError
}
