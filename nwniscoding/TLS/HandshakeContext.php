<?php
namespace nwniscoding\TLS;

use nwniscoding\TLS\Ciphers\CipherInfo;
use nwniscoding\TLS\Ciphers\CipherRegistry;
use nwniscoding\TLS\Handshakes\Certificate;
use nwniscoding\TLS\Handshakes\ClientKeyExchange;
use nwniscoding\TLS\Handshakes\Finished;
use nwniscoding\TLS\Handshakes\ServerKeyExchange;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Handshakes\ServerHello;

final class HandshakeContext{
  private array $handshakes = [];

  private ?CipherInfo $cipherInfo = null;

  private ?ClientHello $clientHello = null;

  private ?ServerHello $serverHello = null;

  private ?ClientKeyExchange $clientKeyExchange = null;

  private ?ServerKeyExchange $serverKeyExchange = null;

  private ?Certificate $certificate = null;

  private ?Finished $finished = null;

  public function addHandshake(Handshake $handshake) : void{
    $this->handshakes[] = $handshake;
    $this->setHandshake($handshake);
  }

  private function setHandshake(Handshake $handshake) : void{
    switch(true){
      case $handshake instanceof ClientHello : 
        $this->clientHello = $handshake; 
        break;
      case $handshake instanceof ServerHello : 
        $this->serverHello = $handshake; 
        $this->cipherInfo = CipherRegistry::getCipher($handshake->cipherSuite);
        break;
      case $handshake instanceof ClientKeyExchange : 
        $this->clientKeyExchange = $handshake; 
        break;
      case $handshake instanceof ServerKeyExchange : 
        $this->serverKeyExchange = $handshake; 
        break;
      case $handshake instanceof Certificate : 
        $this->certificate = $handshake; 
        break;
      case $handshake instanceof Finished : 
        $this->finished = $handshake; 
        break;
    }
  }

  public function getClientHello() : ?ClientHello{
    return $this->clientHello;
  }

  public function getServerHello() : ?ServerHello{
    return $this->serverHello;
  }

  public function getClientKeyExchange() : ?ClientKeyExchange{
    return $this->clientKeyExchange;
  }

  public function getServerKeyExchange() : ?ServerKeyExchange{
    return $this->serverKeyExchange;
  }

  public function getCertificate() : ?Certificate{
    return $this->certificate;
  }

  public function getFinished() : ?Finished{
    return $this->finished;
  }

  public function getCipherInfo() : ?CipherInfo{
    return $this->cipherInfo;
  }

  public function getHandshakeHash() : string{
    $string = '';

    foreach($this->handshakes as $handshake){
      $string .= $handshake->toBinary();
    }

    return hash($this->cipherInfo->mac, $string, true);
  }

  public function all() : array{
    return $this->handshakes;
  }
}