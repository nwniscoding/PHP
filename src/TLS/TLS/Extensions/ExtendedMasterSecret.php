<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

final class ExtendedMasterSecret extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionType::EXTENDED_MASTER_SECRET);
  }
  
  public function getType(): ExtensionType{
    return ExtensionType::EXTENDED_MASTER_SECRET;
  }
}