<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Exceptions\TLSException;
use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\KeyShareEntry;

final readonly class KeyShare extends Extension{
  public array $keyShares;
  public function __construct(array $keyShares){
    $keys = [];

    foreach($keyShares as $keyShare){
      if(!$keyShare instanceof KeyShareEntry){
        throw new TLSException("All key shares must be instances of KeyShareEntry");
      }

      $keys[$keyShare->group->value] = $keyShare;
    }

    $this->keyShares = $keys;
  }

  public function getType(): ExtensionType{
    return ExtensionType::KEY_SHARE;
  }

  protected function encode(HandshakeType $type) : string{
    $writer = new BufferWriter();

    self::helloCheck($type);

    if($type === HandshakeType::CLIENT_HELLO){
      $writer->writeUint16(0);
      $start = $writer->tell();
  
      foreach($this->keyShares as $keyShare){
        $writer->writeUint16($keyShare->group->value);
        $writer->writeUint16(strlen($keyShare->publicKey));
        $writer->write($keyShare->publicKey);
      }
  
      $writer->writeUint16($writer->tell() - $start, $start - 2);
    }
    else{
      $writer->writeUint16($this->getCurrentKeyShare()->group->value);
      $writer->writeUint16(strlen($this->getCurrentKeyShare()->publicKey));
      $writer->write($this->getCurrentKeyShare()->publicKey);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : self{
    $keyShares = [];

    self::helloCheck($type);

    if($type === HandshakeType::CLIENT_HELLO){
      $size = $reader->readUint16();
      $end = $reader->tell() + $size;
  
      while($reader->tell() < $end){
        $value = $reader->readUint16();
        $group = SupportedGroup::tryFrom($value);
  
        if($group === null){
          throw new TLSEnumException(SupportedGroup::class, $value, "Invalid supported group in key_share extension");
        }
  
        $publicKey = $reader->read($reader->readUint16());
        $keyShares[] = new KeyShareEntry($group, $publicKey);
      }
  
      if($reader->tell() !== $end){
        throw new LengthMismatchException("Invalid key_share extension: size mismatch");
      }
    }
    else{
      $value = $reader->readUint16();
      $group = SupportedGroup::tryFrom($value);
  
      if($group === null){
        throw new TLSEnumException(SupportedGroup::class, $value, "Invalid supported group in key_share extension");
      }
  
      $publicKey = $reader->read($reader->readUint16());
  
      $keyShares[] = new KeyShareEntry($group, $publicKey);
    }

    return new self($keyShares);
  }

  public function getCurrentKeyShare() : KeyShareEntry{
    return array_first($this->keyShares); 
  }

  public function getKeyShareByGroup(SupportedGroup $group) : ?KeyShareEntry{
    return $this->keyShares[$group->value] ?? null;
  }
}