<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\Sessions\Session;

final readonly class SupportedVersion extends Extension{
  public function __construct(public array $versions){}

  public function getType() : ExtensionType{
    return ExtensionType::SUPPORTED_VERSIONS;
  }

  protected function encode(HandshakeType $type) : string{
    self::helloCheck($type);
    $writer = new BufferWriter();

    if($type === HandshakeType::CLIENT_HELLO){
      $writer->writeUint8(count($this->versions) * 2);

      foreach($this->versions as $version){
        $writer->writeUint16($version->value);
      }
    }
    else{
      $writer->writeUint16($this->versions[0]->value);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : self{
    self::helloCheck($type);
    $versions = [];

    if($type === HandshakeType::CLIENT_HELLO){
      $length = $reader->readUint8();

      if($length % 2 !== 0){
        throw new LengthMismatchException("Invalid SupportedVersion extension: length must be a multiple of 2");
      }

      $length /= 2;

      for($i = 0; $i < $length; $i++){
        $value = $reader->readUint16();
        $version = Version::tryFrom($value);

        if($version === null){
          throw new TLSEnumException(Version::class, $value, "Invalid version in supported_version extension");
        }
        
        $versions[] = $version;
      }
    }
    else{
      $value = $reader->readUint16();
      $version = Version::tryFrom($value);

      if($version === null){
        throw new TLSEnumException(Version::class, $value, "Invalid version in supported_version extension");
      }

      $versions[] = $version;
    }

    return new self($versions);
  }
}