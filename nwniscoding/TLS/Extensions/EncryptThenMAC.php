<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionType;

final readonly class EncryptThenMAC extends Extension{
  use EmptyExtensionTrait;

  public function getType() : ExtensionType{
    return ExtensionType::ENCRYPT_THEN_MAC;
  }
}