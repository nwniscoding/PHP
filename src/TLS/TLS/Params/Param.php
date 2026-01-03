<?php
namespace TLS\Params;

use OpenSSLAsymmetricKey;
use Stringable;

abstract class Param implements Stringable{
  private OpenSSLAsymmetricKey $key;

  public function __construct(OpenSSLAsymmetricKey $key){
    $this->key = $key;
  }

  public function getKey(): OpenSSLAsymmetricKey{
    return $this->key;
  }

  abstract public function __toString(): string;
}