<?php
namespace nwniscoding\TLS\Handshakes;

use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\HandshakeContext;
use nwniscoding\TLS\Params\DHEParam;
use nwniscoding\TLS\Params\ECDHEParam;
use nwniscoding\TLS\Params\Param;

final readonly class ClientKeyExchange extends Handshake{
  public ?Param $keyExchangeParam;

  public ?string $identity;

  public function __construct(?Param $keyExchangeParam, ?string $identity){
    $this->keyExchangeParam = $keyExchangeParam;
    $this->identity = $identity;
  }

  public function getType() : HandshakeType{
    return HandshakeType::CLIENT_KEY_EXCHANGE;
  }

  protected function encode() : string{
    $writer = new BufferWriter();
    
    if($this->identity !== null){
      $writer->writeUint16(strlen($this->identity));
      $writer->write($this->identity);
    }

    if($this->keyExchangeParam !== null){
      $writer->write($this->keyExchangeParam);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    $identity = null;
    $param = null;
    $info = $context->getCipherInfo();

    if($info->authentication === 'psk'){
      $identity = $reader->read($reader->readUint16());
    }

    $param = match($info->keyExchange){
      'psk' => null,
      'ecdhe' => ECDHEParam::decode($reader, HandshakeType::CLIENT_KEY_EXCHANGE),
      'dhe' => DHEParam::decode($reader, HandshakeType::CLIENT_KEY_EXCHANGE),
    };

    return new self($param, $identity);
  }
}