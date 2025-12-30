<?php
namespace TLS;

use Stringable;

/**
 * Interface for TLS Messages with encode/decode methods
 */
interface MessageInterface extends Stringable{
  public function encode(): string;

  public static function decode(string $data): static;
}