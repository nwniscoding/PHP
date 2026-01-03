<?php
namespace TLS\Params;

use OpenSSLAsymmetricKey;
use TLS\Enums\SupportedGroup;

class ECDHEParam extends Param{
  private SupportedGroup $curve_name;

  public function __construct(SupportedGroup $curve_name, OpenSSLAsymmetricKey $key){
    parent::__construct($key);
    $this->curve_name = $curve_name;
  }

  public function getCurveName(): SupportedGroup{
    return $this->curve_name;
  }

  public static function create(SupportedGroup $curve_name): static{
    $key = openssl_pkey_new([
      'private_key_type' => OPENSSL_KEYTYPE_EC,
      'curve_name' => $curve_name->getOpenSSLName()
    ]);

    return new static($curve_name, $key);
  }

  public function __tostring(): string{
    $key = openssl_pkey_get_details($this->getKey());
    $public_key = "\4" . $key['ec']['x'] . $key['ec']['y'];

    return pack(
      'CnCa*', 
      3, 
      $this->curve_name->value,
      strlen($public_key),
      $public_key
    );
  }
}