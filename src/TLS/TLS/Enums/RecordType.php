<?php
namespace TLS\Enums;

/**
 * Enumeration of TLS Record Types as per IANA registry.
 * 
 * @package Enums
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
 */
enum RecordType : int{
  case CHANGE_CIPHER = 20;

  case ALERT = 21;

  case HANDSHAKE = 22;

  case APPLICATION_DATA = 23;

  case HEARTBEAT = 24;

  case TLS12_CID = 25;

  case ACK = 26;

  case RETURN_ROUTABILITY_CHECK = 27;
}