<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\CipherSuite;
use TLS\Enums\ExtensionType;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\ExtensionFactory;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ClientHello extends Handshake{
  private Version $version;

  private string $random;

  private string $session_id = '';

  private array $cipher_suites = [];

  private array $extensions = [];

  public function __construct(Context $context){
    parent::__construct($context);
    $this->random = openssl_random_pseudo_bytes(32);
  }

  public function setVersion(Version $version): self{
    $this->version = $version;
    return $this;
  }

  public function getVersion(): Version{
    return $this->version;
  }

  public function getRandom(): string{
    return $this->random;
  }

  public function setSessionId(string $session_id): self{
    $this->session_id = $session_id;
    return $this;
  }

  public function getSessionId(): string{
    return $this->session_id;
  }

  public function setCipherSuites(array $ciphers): self{
    $this->cipher_suites = $ciphers;
    return $this;
  }

  public function getCipherSuites(): array{
    return $this->cipher_suites;
  }

  public function setExtensions(array $extensions): self{
    $this->extensions = $extensions;
    return $this;
  }

  public function getExtensions(): array{
    return $this->extensions;
  }

  public function hasExtension(ExtensionType $type): bool{
    return array_key_exists($type->value, $this->extensions);
  }

  public function encode(): BufferWriter{
    $extension = join('', $this->extensions);
    $cipher_count = count($this->cipher_suites) * 2;

    /**
     * 41 bytes comes from the fixed-size fields in ClientHello:
     * - 2 bytes: version
     * - 32 bytes: random
     * - 1 byte: session id length
     * - 2 bytes: cipher suites length
     * - 2 bytes: compression methods length
     * - 2 bytes: extensions length
     */
    $writer = new BufferWriter(41 + strlen($this->session_id) + $cipher_count + strlen($extension));

    $writer
    ->setU16($this->version->value) 
    ->write($this->random) 
    ->setU8(strlen($this->session_id)) 
    ->write($this->session_id) 
    ->setU16(count($this->cipher_suites) * 2); 

    foreach($this->cipher_suites as $cipher){
      $writer->setU16($cipher->value);
    }

    return $writer
    ->setU16(1 << 8) 
    ->setU16(strlen($extension)) 
    ->write($extension);
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    $handshake->version = Version::from($reader->getU16());
    $handshake->random = $reader->read(32);
    $handshake->session_id = $reader->read($reader->getU8());

    for($i = 0, $size = $reader->getU16(); $i < $size; $i += 2){
      $handshake->cipher_suites[] = CipherSuite::from($reader->getU16());
    }

    $reader->move(2); // We do not care about compression methods

    $total_extension_size = $reader->getU16();
    $offset = 0;

    while($offset < $total_extension_size){
      $extension_type = $reader->getU16();
      $extension_size = $reader->getU16();
      $extension_data = $reader->read($extension_size);

      $handshake->extensions[$extension_type] = ExtensionFactory::loadExtension(
        $extension_type,
        $extension_data
      );

      $offset += 4 + $extension_size;
    }

    return $handshake;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::CLIENT_HELLO;
  }

  public function __debugInfo(): array{
    return [
      'type' => $this->getType(),
      'version' => $this->version,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suites' => array_map(fn($c) => $c->name, $this->cipher_suites),
      'extensions' => $this->extensions
    ];
  }
}