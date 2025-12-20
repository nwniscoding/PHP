<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;

class RenegotiationInfoExtension extends Extension{
  private string $data;

  public function __construct(string $data = ''){
    parent::__construct(ExtensionEnum::RENEGOTIATION_INFO);
    $this->data = $data;
  }

  public function encode(): string{
    return \chr(\strlen($this->data)) . $this->data;
  }

  public static function decode(string $data): self{
    $length = \ord($data[0]);
    $renegotiation_data = \substr($data, 1, $length);
    return new self($renegotiation_data);
  }

  public function getData(): mixed{
    return $this->data;
  }
}