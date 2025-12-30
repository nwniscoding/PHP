<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

class SessionTicketExtension extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionType::SESSION_TICKET);
  }
}