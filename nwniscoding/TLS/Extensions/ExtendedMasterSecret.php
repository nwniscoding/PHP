<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionType;

final readonly class ExtendedMasterSecret extends Extension{
  use EmptyExtensionTrait;

  public function getType() : ExtensionType{
    return ExtensionType::EXTENDED_MASTER_SECRET;
  }
}