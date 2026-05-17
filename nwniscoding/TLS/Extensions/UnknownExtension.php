<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use RuntimeException;

final readonly class UnknownExtension extends Extension{
  private ExtensionType $type;

  public function __construct(int $type, public string $data){
    $this->type = ExtensionType::from($type);
  }

  public function getType() : ExtensionType{
    return $this->type;
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : self{
    throw new RuntimeException('Unknown extensions cannot be decoded.');
  }

  protected function encode(HandshakeType $type) : string{
    return $this->data;
  }
}