<?php
namespace TLS\Params;

final class RSAParam extends Param{
  private string $encrypted_pre_master_secret;

  public function __construct(string $encrypted_pre_master_secret){
    $this->encrypted_pre_master_secret = $encrypted_pre_master_secret;
  }

  public function encode(): string{
    $length = strlen($this->encrypted_pre_master_secret);
    
    return pack('na*', $length, $this->encrypted_pre_master_secret);
  }
}