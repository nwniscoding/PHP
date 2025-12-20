<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;

abstract class Extension{
  public function __construct(protected readonly ExtensionEnum $type){}

  public function getType(): ExtensionEnum{
    return $this->type;
  }

  public abstract function encode(): string;

  public abstract function getData(): mixed;

  public static abstract function decode(string $data): self;
}