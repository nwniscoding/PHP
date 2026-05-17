<?php
namespace nwniscoding\TLS;

use nwniscoding\TLS\Enums\SupportedGroup;
use OpenSSLAsymmetricKey;

final readonly class KeyShareEntry{
  public SupportedGroup $group;

  public ?OpenSSLAsymmetricKey $privateKey;

  public string $publicKey;

  public function __construct(SupportedGroup $group, ?string $publicKey = null){
    $this->group = $group;

    if($publicKey !== null){
      $this->publicKey = $publicKey;
    }
    else{
      $this->privateKey = $group->createPrivateKey();
      $this->publicKey = $group->exportPublicKey($this->privateKey);
    }
  }
}