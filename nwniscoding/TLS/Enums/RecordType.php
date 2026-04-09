<?php
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Record Types as per IANA registry.
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