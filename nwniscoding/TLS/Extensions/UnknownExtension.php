<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Sessions\Session;
use RuntimeException;

final readonly class UnknownExtension extends Extension{
  private ExtensionType $type;

  public function __construct(int $type, public string $data){
    $this->type = ExtensionType::from($type);
  }

  public function getType() : ExtensionType{
    return $this->type;
  }

  public static function decode(BufferReader $reader, string $class) : self{
    throw new RuntimeException('Unknown extensions cannot be decoded.');
  }

  protected function encode() : string{
    return $this->data;
  }
}