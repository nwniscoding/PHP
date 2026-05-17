<?php
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Handshake Types as per IANA registry.
 */
enum HandshakeType : int{
  case HELLO_REQUEST = 0;

  case CLIENT_HELLO = 1;

  case SERVER_HELLO = 2;

  case CERTIFICATE = 11;

  case SERVER_HELLO_DONE = 14;

  case CLIENT_KEY_EXCHANGE = 16;

  case SERVER_KEY_EXCHANGE = 12;

  case FINISHED = 20;

  case ENCRYPTED = 255;

  /**
   * Get the next possible handshake types that can follow the current handshake type in the TLS handshake process.
   * @return HandshakeType[] An array of HandshakeType enums representing the next possible handshake types.
   */
  public function nextState() : array{
    return match($this){
      self::HELLO_REQUEST => [
        self::CLIENT_HELLO
      ],
      self::CLIENT_HELLO => [
        self::SERVER_HELLO
      ],
      self::SERVER_HELLO => [
        self::CLIENT_HELLO,
        self::CERTIFICATE, 
        self::SERVER_KEY_EXCHANGE, 
        self::SERVER_HELLO_DONE
      ],
      self::CERTIFICATE => [
        self::SERVER_KEY_EXCHANGE, 
        self::SERVER_HELLO_DONE
      ],
      self::SERVER_KEY_EXCHANGE => [
        self::SERVER_HELLO_DONE
      ],
      self::SERVER_HELLO_DONE => [
        self::CLIENT_KEY_EXCHANGE
      ],
      self::CLIENT_KEY_EXCHANGE => [
        self::FINISHED
      ],
      self::FINISHED => [
      ]
    };
  }
}