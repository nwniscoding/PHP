<?php
namespace TLS;

use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\Extension;
use TLS\Handshakes\Certificate;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ClientKeyExchange;
use TLS\Handshakes\Handshake;
use TLS\Handshakes\ServerHello;
use TLS\Handshakes\ServerKeyExchange;

final class Context{
  private Version $version = Version::TLS_12;

  private ?ClientHello $client_hello;

  private ?ServerHello $server_hello;

  private ?ServerKeyExchange $server_key_exchange;

  private ?ClientKeyExchange $client_key_exchange;

  private ?Certificate $client_certificate;

  private ?Certificate $server_certificate;

  private ?CipherSuite $cipher_suite;

  public function __construct(Version $version){
    $this->version = $version;
  }

  public function setHandshake(Handshake $handshake): void{
    switch($handshake->getType()){
      case HandshakeType::CLIENT_HELLO:
        $this->client_hello = $handshake;
        break;
      case HandshakeType::SERVER_HELLO:
        $this->server_hello = $handshake;
        break;
      case HandshakeType::SERVER_KEY_EXCHANGE:
        $this->server_key_exchange = $handshake;
        break;
      case HandshakeType::CLIENT_KEY_EXCHANGE:
        $this->client_key_exchange = $handshake;
        break;
    }
  }

  public function hasHandshake(HandshakeType $type): bool{
    return match($type){
      HandshakeType::CLIENT_HELLO => isset($this->client_hello),
      HandshakeType::SERVER_HELLO => isset($this->server_hello),
      HandshakeType::SERVER_KEY_EXCHANGE => isset($this->server_key_exchange),
      HandshakeType::CLIENT_KEY_EXCHANGE => isset($this->client_key_exchange),
      default => false,
    };
  }
}