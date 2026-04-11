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
use nwniscoding\TLS\Params\RSAParam;
use nwniscoding\TLS\Params\SignatureParam;

final readonly class ServerKeyExchange extends Handshake{
  public ?Param $keyExchangeParam;
  
  public ?SignatureParam $signatureParam;
  
  public ?string $identityHint;

  public function __construct(?Param $keyExchangeParam, ?SignatureParam $signatureParam = null, ?string $identityHint = null){
    $this->keyExchangeParam = $keyExchangeParam;
    $this->signatureParam = $signatureParam;
    $this->identityHint = $identityHint;
  }

  public function getType() : HandshakeType{
    return HandshakeType::SERVER_KEY_EXCHANGE;
  }

  protected function encode() : string{
    $writer = new BufferWriter();

    if($this->identityHint !== null){
      $writer->writeUInt16(strlen($this->identityHint));
      $writer->write($this->identityHint);
    }

    if($this->keyExchangeParam !== null){
      $writer->write($this->keyExchangeParam);
    }

    if($this->signatureParam !== null){
      $writer->write($this->signatureParam);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    $identityHint = null;
    $keyExchangeParam = null;
    $signatureParam = null;
    $info = $context->getCipherInfo();

    if($info->authentication === 'psk'){
      $identityHint = $reader->read($reader->readUInt16());
    }

    $keyExchangeParam = match($info->keyExchange){
      'rsa' => RSAParam::decode($reader, HandshakeType::SERVER_KEY_EXCHANGE),
      'dhe' => DHEParam::decode($reader, HandshakeType::SERVER_KEY_EXCHANGE),
      'ecdhe' => ECDHEParam::decode($reader, HandshakeType::SERVER_KEY_EXCHANGE),
      'psk' => null
    };

    $signatureParam = match($info->authentication){
      'ecdsa', 'rsa' => SignatureParam::decode($reader, HandshakeType::SERVER_KEY_EXCHANGE),
      'psk' => null
    };

    return new self($keyExchangeParam, $signatureParam, $identityHint);
  }
}