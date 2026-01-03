<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Utils\BufferWriter;

class RenegotiationInfo extends Extension{
  use EmptyExtensionTrait;
  
  public function __construct(){
    parent::__construct(ExtensionType::RENEGOTIATION_INFO);
  }

  public function encode(): BufferWriter{
    return new BufferWriter("\0");
  }
}