<?php
namespace TLS;

use TLS\Enums\CipherSuite;
use TLS\Enums\Version;
use TLS\Extensions\Extension;

class Config{
  private Version $version;

  private array $cipher_suites = [];

  private array $extensions = [];

  public function __construct(Version $version){
    $this->version = $version;
  }

  public function getVersion(): Version{
    return $this->version;
  }

  public function getCipherSuites(): array{
    return $this->cipher_suites;
  }

  public function getExtensions(): array{
    return $this->extensions;
  }

  public function addCipherSuite(CipherSuite $cipher_suite): void{
    $this->cipher_suites[] = $cipher_suite;
  }

  public function addExtension(Extension $extension): void{
    $this->extensions[$extension->getType()->value] = $extension;
  }
}