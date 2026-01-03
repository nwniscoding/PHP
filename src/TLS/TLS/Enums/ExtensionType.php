<?php
namespace TLS\Enums;

/**
 * Enumeration of TLS Extension Types as per IANA registry.
 * 
 * @package Enums
 * @see https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 */
enum ExtensionType : int{
  case SERVER_NAME = 0;
  
  case MAX_FRAGMENT_LENGTH = 1;
  
  case CLIENT_CERTIFICATE_URL = 2;
  
  case TRUSTED_CA_KEYS = 3;
  
  case TRUNCATED_HMAC = 4;
  
  case STATUS_REQUEST = 5;
  
  case USER_MAPPING = 6;
  
  case CLIENT_AUTHZ = 7;
  
  case SERVER_AUTHZ = 8;
  
  case CERT_TYPE = 9;
  
  case SUPPORTED_GROUPS = 10;
  
  case EC_POINT_FORMATS = 11;
  
  case SRP = 12;
  
  case SIGNATURE_ALGORITHMS = 13;
  
  case USE_SRTP = 14;
  
  case HEARTBEAT = 15;
  
  case APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
  
  case STATUS_REQUEST_V2 = 17;
  
  case SIGNED_CERTIFICATE_TIMESTAMP = 18;
  
  case CLIENT_CERTIFICATE_TYPE = 19;
  
  case SERVER_CERTIFICATE_TYPE = 20;
  
  case PADDING = 21;
  
  case ENCRYPT_THEN_MAC = 22;
  
  case EXTENDED_MASTER_SECRET = 23;
  
  case TOKEN_BINDING = 24;
  
  case CACHED_INFO = 25;
  
  case TLS_LTS = 26;
  
  case COMPRESS_CERTIFICATE = 27;
  
  case RECORD_SIZE_LIMIT = 28;
  
  case PWD_PROTECT = 29;
  
  case PWD_CLEAR = 30;
  
  case PASSWORD_SALT = 31;
  
  case TICKET_PINNING = 32;
  
  case TLS_CERT_WITH_EXTERN_PSK = 33;
  
  case DELEGATED_CREDENTIAL = 34;
  
  case SESSION_TICKET = 35;
  
  case TLMSP = 36;
  
  case TLMSP_PROXYING = 37;
  
  case TLMSP_DELEGATE = 38;
  
  case SUPPORTED_EKT_CIPHERS = 39;
  
  case PRE_SHARED_KEY = 41;
  
  case EARLY_DATA = 42;
  
  case SUPPORTED_VERSIONS = 43;
  
  case COOKIE = 44;
  
  case PSK_KEY_EXCHANGE_MODES = 45;
  
  case CERTIFICATE_AUTHORITIES = 47;
  
  case OID_FILTERS = 48;
  
  case POST_HANDSHAKE_AUTH = 49;
  
  case SIGNATURE_ALGORITHMS_CERT = 50;
  
  case KEY_SHARE = 51;
  
  case TRANSPARENCY_INFO = 52;
  
  case CONNECTION_ID = 54;
  
  case EXTERNAL_ID_HASH = 55;
  
  case EXTERNAL_SESSION_ID = 56;
  
  case QUIC_TRANSPORT_PARAMETERS = 57;
  
  case TICKET_REQUEST = 58;
  
  case DNSSEC_CHAIN = 59;
  
  case SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS = 60;
  
  case RRC = 61;
  
  case TLS_FLAGS = 62;
  
  case ECH_OUTER_EXTENSIONS = 64768;
  
  case ENCRYPTED_CLIENT_HELLO = 65037;
  
  case RENEGOTIATION_INFO = 65281;

  case UNKNOWN = -1;
}