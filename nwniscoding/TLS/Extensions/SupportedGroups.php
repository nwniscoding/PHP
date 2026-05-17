<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\Sessions\Session;
use function count;
use InvalidArgumentException;

final readonly class SupportedGroups extends Extension{
  public array $groups;

  public int $size;

  public function __construct(array $groups = []){
    foreach($groups as $group){
      if(!($group instanceof SupportedGroup)){
        throw new TLSEnumException(SupportedGroup::class, $group, 'All elements of $groups must be instances of SupportedGroup enum.');
      }
    }

    $this->groups = $groups;
    $this->size = count($this->groups) * 2;
  }

  public function getType() : ExtensionType{
    return ExtensionType::SUPPORTED_GROUPS;
  }

  protected function encode(HandshakeType $type) : string{
    self::helloCheck($type);

    $writer = new BufferWriter();
    $groups = $this->groups;

    $writer->writeUint16($this->size);

    foreach($groups as $group){
      $writer->writeUint16($group->value);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : static{
    self::helloCheck($type);

    $size = $reader->readUint16() / 2;
    $groups = [];

    for($i = 0; $i < $size; $i++){
      $value = $reader->readUint16();
      $group = SupportedGroup::tryFrom($value);

      if($group === null){
        throw new TLSEnumException(SupportedGroup::class, $value, "Invalid group value: $value");
      }

      $groups[] = $group;
    }

    if(!$reader->EOF()){
      throw new LengthMismatchException("Invalid Support Group length.");
    }

    return new static($groups);
  }

  public function __debuginfo() : array{
    return [];
  }
}