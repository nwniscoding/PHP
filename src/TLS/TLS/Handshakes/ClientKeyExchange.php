<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;
use TLS\Params\Param;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ClientKeyExchange extends Handshake{
  private ?Param $param = null;

  private ?string $identity = null;

  private BufferReader $raw_data;

  public static function getType(): HandshakeType{
    return HandshakeType::CLIENT_KEY_EXCHANGE;
  }

  public function setParam(Param $param): self{
    $this->param = $param;
    
    return $this;
  }

  public function getParam(): ?Param{
    return $this->param;
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

  public static function decode(BufferReader $reader): static{
    $handshake = new self;

    $handshake->raw_data = $reader;

    return $handshake;
  }

  private function initRawData(ServerHello $server_hello): void{
    $cipher = $server_hello->getCipherSuite();

    if($cipher->metadata()['authentication'] === 'PSK'){
      $identity_length = $this->raw_data->getU16();
      $this->identity = $this->raw_data->read($identity_length);
    }

    
  }
}