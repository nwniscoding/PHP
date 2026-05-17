<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\SignatureAlgorithm;
use nwniscoding\TLS\Exceptions\InvalidCipherSuiteException;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\Exceptions\TLSException;
use function count;
use InvalidArgumentException;

final readonly class SignatureAlgorithms extends Extension{
  public array $signatures;

  public int $size;
  
  public function __construct(array $signatures = []){
    $this->validateSignatures($signatures);

    $this->signatures = $signatures;
    $this->size = count($this->signatures) * 2;
  }

  public function getType(): ExtensionType{
    return ExtensionType::SIGNATURE_ALGORITHMS;
  }

  protected function encode(HandshakeType $type) : string{
    self::helloCheck($type);

    $writer = new BufferWriter();
    $signatures = $this->signatures;

    $writer->writeUint16($this->size);

    foreach($signatures as $signature){
      $writer->writeUint16($signature->value);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : static{
    self::helloCheck($type);

    $size = $reader->readUint16();

    if($size % 2 !== 0){
      throw new LengthMismatchException('Invalid SignatureAlgorithms: Signature length must be a multiple of 2');
    }

    $size /= 2;
    
    $signatures = [];


    for($i = 0; $i < $size; $i++){
      $value = $reader->readUint16();
      $signature = SignatureAlgorithm::tryFrom($value);

      if($signature === null){
        throw new TLSEnumException(SignatureAlgorithm::class, $value, "Invalid signature algorithm in signature_algorithms extension");
      }

      $signatures[] = $signature;
    }


    if(!$reader->EOF()){
      throw new LengthMismatchException("Invalid Signature Algorithm length");
    }

    return new static($signatures);
  }

  private function validateSignatures(array $signatures) : void{
    foreach($signatures as $signature){
      if(!($signature instanceof SignatureAlgorithm)){
        throw new TLSException("All elements of signatures must be instances of SignatureAlgorithm enum.");
      }
    }
  }

  public function __debuginfo() : array{
    return [];
  }
}