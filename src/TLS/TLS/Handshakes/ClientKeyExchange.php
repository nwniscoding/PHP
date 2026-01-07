<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Params\Param;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ClientKeyExchange extends Handshake{
  private ?Param $param = null;

  private ?string $identity = null;

  public static function getType(): HandshakeType{
    return HandshakeType::CLIENT_KEY_EXCHANGE;
  }

  public function setParam(Param $param): self{
    $this->param = $param;

    return $this;
  }

  public function setPSKIdentity(string $identity): self{
    $this->identity = $identity;
    
    return $this;
  }

  public function getPSKIdentity(): ?string{
    return $this->identity;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;

    if($this->identity !== null){
      $writer
      ->setU16(strlen($this->identity))
      ->write($this->identity);
    }

    if($this->param !== null){
      $writer->write($this->param);
    }

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    return $handshake;
  }
}