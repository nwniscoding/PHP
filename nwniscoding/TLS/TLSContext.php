<?php
namespace nwniscoding\TLS;

use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\SignatureAlgorithm;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Sessions\ClientSession;
use Socket;

final class TLSContext{
  public readonly Version $version;
  
  private array $cipherSuites = [];

  private array $groups = [];

  private array $signatures = [];

  private array $pskIdentities = [];

  public function __construct(Version $version){
    $this->version = $version;
  }

  public function addCipherSuite(CipherSuite ...$cipherSuite) : void{
    foreach ($cipherSuite as $suite) {
      $this->cipherSuites[$suite->value] = $suite;
    }
  }

  public function getCipherSuites() : array{
    return $this->cipherSuites;
  }

  public function addGroup(SupportedGroup ...$groups) : void{
    foreach($groups as $group){
      $this->groups[$group->value] = $group;
    }
  }

  public function getGroups() : array{
    return $this->groups;
  }

  public function addSignature(SignatureAlgorithm ...$signatures) : void{
    foreach($signatures as $signature){
      $this->signatures[$signature->value] = $signature;
    }
  }

  public function getSignatures() : array{
    return $this->signatures;
  }

  public function setPSKIdentity(string $identity, string $psk) : void{
    $this->pskIdentities[$identity] = $psk;
  }

  public function getPSK(string $identity) : ?string{
    return $this->pskIdentities[$identity] ?? null;
  }

  public function createClientSession(Socket $socket, ?string $psk = null) : ClientSession{
    return new ClientSession($socket, $this, $psk);
  }
}