<?php
namespace TLS\Handshakes;

use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\ExtensionFactory;
use TLS\TLSException;
use TLS\Utils\BufferReader;

class ClientHello extends Handshake{
  private Version $version;

  private string $random;

  private string $session_id = '';

  private array $cipher_suites = [];

  private array $extensions = [];

  public function __construct(){
    parent::__construct(HandshakeType::CLIENT_HELLO);
    
    $this->random = openssl_random_pseudo_bytes(32);
  }

  public function setVersion(Version $version): void{
    $this->version = $version;
  }

  public function getVersion(): Version{
    return $this->version;
  }

  public function getRandom(): string{
    return $this->random;
  }

  public function encode(): string{
    $cipher_suites = pack(
      'n*',
      ...array_map(fn(CipherSuite $cs) => $cs->value, $this->cipher_suites)
    );

    $extensions = join('', $this->extensions);

    return pack(
      'na*Ca*na*n2a*',
      $this->version->value,
      $this->random, 
      \strlen($this->session_id),
      $this->session_id,
      \count($this->cipher_suites) * 2,
      $cipher_suites,
      1 << 8,
      \strlen($extensions),
      $extensions
    );
  }

  public static function decode(string $data): static{
    $handshake = new self;
    $buffer = new BufferReader($data);
    
    $handshake->version = Version::from($buffer->getU16());
    $handshake->random = $buffer->read(32);
    $handshake->session_id = $buffer->read($buffer->getU8());

    for($i = $buffer->getU16(); $i > 0; $i -= 2){
      $handshake->cipher_suites[] = CipherSuite::from($buffer->getU16());
    }

    $buffer->getU16(); // Ignore compression methods since they are an artifact

    $ext_size = $buffer->getU16() + $buffer->getOffset();

    while(!$buffer->isEOF()){
      $extension_type = $buffer->getU16();

      $handshake->extensions[$extension_type] = ExtensionFactory::loadExtension(
        $extension_type,
        $buffer->read($buffer->getU16())
      );
    }

    return $handshake;
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
      'version' => $this->version->name,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suites' => array_map(fn(CipherSuite $e) => $e->name, $this->cipher_suites),
      'extensions' => $this->extensions
    ];
  }
  
  public function __debugInfo(): array{
    return [
      'type' => $this->type,
      'version' => $this->version,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suites' => $this->cipher_suites,
      'extensions' => $this->extensions
    ];
  }
}