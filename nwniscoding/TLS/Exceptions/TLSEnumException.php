<?php
namespace nwniscoding\TLS\Exceptions;

final class TLSEnumException extends TLSException{
  public function __construct(public readonly string $enum, public readonly int $value, public readonly string $field){
    $hex = dechex($value);
    parent::__construct("Invalid {$enum} for {$field}: 0x{$hex}");
  }
}