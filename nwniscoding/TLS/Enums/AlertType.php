<?php
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Alert Types as per IANA registry.
 */
enum AlertType : int{
  case CLOSE_NOTIFY = 0;

  case UNEXPECTED_MESSAGE = 10;

  case BAD_RECORD_MAC = 20;

  case DECRYPTION_FAILED = 21;

  case RECORD_OVERFLOW = 22;

  case DECOMPRESSION_FAILURE = 30;

  case HANDSHAKE_FAILURE = 40;

  case NO_CERTIFICATE = 41;

  case BAD_CERTIFICATE = 42;

  case UNSUPPORTED_CERTIFICATE = 43;

  case CERTIFICATE_REVOKED = 44;

  case CERTIFICATE_EXPIRED = 45;

  case CERTIFICATE_UNKNOWN = 46;

  case ILLEGAL_PARAMETER = 47;

  case UNKNOWN_CA = 48;

  case ACCESS_DENIED = 49;

  case DECODE_ERROR = 50;

  case DECRYPT_ERROR = 51;

  case EXPORT_RESTRICTION = 60;

  case PROTOCOL_VERSION = 70;

  case INSUFFICIENT_SECURITY = 71;

  case INTERNAL_ERROR = 80;

  case USER_CANCELED = 90;
}