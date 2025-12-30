<?php
namespace TLS\Enums;

/**
 * Enumeration of TLS Handshake Types as per IANA registry.
 * 
 * @package Enums
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
 */
enum HandshakeType : int{
  case HELLO_REQUEST = 0;

  case CLIENT_HELLO = 1;

  case SERVER_HELLO = 2;

  case CERTIFICATE = 11;

  case SERVER_HELLO_DONE = 14;

  case CLIENT_KEY_EXCHANGE = 16;

  case FINISHED = 20;
}