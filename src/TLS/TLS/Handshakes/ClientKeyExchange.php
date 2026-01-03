<?php
namespace TLS\Handshakes;

use Exception;
use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Params\Param;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;
use TLS\Handshakes\ServerHello;

class ClientKeyExchange extends Handshake{
  private ?Param $param;

  private ?string $identity;

  public function __construct(Context $context){
    parent::__construct($context);
  }

  public function setParam(Param $param): self{
    $this->param = $param;
    return $this;
  }

  public function getParam(): ?Param{
    return null;
  }

  public function setPSKIdentity(string $identity): self{
    $this->identity = $identity;
    return $this;
  }

  public function getPSKIdentity(): ?string{
    return $this->identity;
  }

  public function encode(): BufferWriter{
    /** @var ServerHello */
    $server_hello = $this->context->getHandshake(HandshakeType::SERVER_HELLO);
    $metadata = $server_hello->getCipherSuite()->metadata();
    $writer = new BufferWriter;

    if($metadata['authentication'] === 'PSK'){
      $writer
      ->setU16(strlen($this->identity))
      ->write($this->identity);
    }
    else{
      $writer->write($this->param);
    }

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    return $handshake;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::CLIENT_KEY_EXCHANGE;
  }
}