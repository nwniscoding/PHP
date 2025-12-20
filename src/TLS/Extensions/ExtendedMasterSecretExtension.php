<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;

class ExtendedMasterSecretExtension extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionEnum::EXTENDED_MASTER_SECRET);
  }
}