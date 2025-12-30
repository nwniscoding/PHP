<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Utils\Buffer;

class RenegotiationInfo extends Extension{
  private string $data;

  public function __construct(string $data = ''){
    parent::__construct(ExtensionType::RENEGOTIATION_INFO);
    $this->data = $data;
  }

  public function encode(): string{
    return \chr(\strlen($this->data)) . $this->data;
  }

  public static function decode(string $data): static{
    // $data = new Buffer($data);
    // $renegotiation_data = \substr($data, 1, $data->getU8());
    // return new self($renegotiation_data);

    return new self(1);
  }

  public function getData(): mixed{
    return $this->data;
  }
}