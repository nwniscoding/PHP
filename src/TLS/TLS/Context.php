<?php
namespace TLS;

use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Handshakes\Handshake;
use TLS\Handshakes\ServerHello;

final class Context{
  /**
   * @return array<int, Handshake>
   */
  private array $handshakes = [];

  public function __construct(private Version $version){}

  public function getVersion(): Version{
    return $this->version;
  }

  public function getCipher(): ?CipherSuite{
    /** @var ServerHello */
    $server_hello = $this->getHandshake(HandshakeType::SERVER_HELLO);

    if($server_hello === null){
      return null;
    }

    return $server_hello->getCipherSuite();
  }

  public function hasHandshake(HandshakeType $type): bool{
    return isset($this->handshakes[$type->value]);
  }

  public function getHandshake(HandshakeType $type): ?Handshake{
    return $this->handshakes[$type->value] ?? null;
  }

  public function addHandshake(Handshake $handshake): void{
    $this->handshakes[$handshake->getType()->value] = $handshake;
  }

  public function getHandshakeHash(): string{
    $cipher_name = $this->getCipher()->name;
    $hash = substr($cipher_name, strrpos($cipher_name, '_') + 1);
    $text = join('', $this->handshakes);

    return hash($hash, $text, true);
  }
}