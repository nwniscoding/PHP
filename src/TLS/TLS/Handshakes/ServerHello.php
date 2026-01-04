<?php
namespace TLS\Handshakes;

use TLS\Enums\CipherSuite;
use TLS\Enums\ExtensionType;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\Extension;
use TLS\Extensions\ExtensionFactory;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ServerHello extends Handshake{
  private Version $version;

  private string $random;

  private string $session_id = '';

  private CipherSuite $cipher_suite;

  private array $extensions = [];

  public function __construct(){
    $this->random = openssl_random_pseudo_bytes(32);
  }

  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_HELLO;
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

  public function setSessionId(string $session_id = ''): self{
    $this->session_id = $session_id;
    return $this;
  }

  public function getSessionId(): string{
    return $this->session_id;
  }

  public function setCipherSuite(CipherSuite $cipher_suite): self{
    $this->cipher_suite = $cipher_suite;
    return $this;
  }

  public function getCipherSuite(): CipherSuite{
    return $this->cipher_suite;
  }

  public function addExtension(Extension $extension): self{
    $this->extensions[$extension->getType()->value] = $extension;
    return $this;
  }

  public function getExtensions(): array{
    return $this->extensions;
  }

  public function hasExtension(ExtensionType $type): bool{
    return \array_key_exists($type->value, $this->extensions);
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    $extension = join('', $this->extensions);

    $writer
    ->setU16($this->version->value)
    ->write($this->random)
    ->setU8(strlen($this->session_id))
    ->write($this->session_id)
    ->setU16($this->cipher_suite->value)
    ->setU8(0);

    if(($str_len = \strlen($extension)) > 0){
      $writer->setU16($str_len)->write($extension);
    }

    return $writer;
  }

  public static function decode(BufferReader $reader): static{
    $handshake = new self;

    $handshake->version = Version::from($reader->getU16());
    $handshake->random = $reader->read(32);
    $handshake->session_id = $reader->read($reader->getU8());
    $handshake->cipher_suite = CipherSuite::from($reader->getU16());

    $reader->move(1);

    // No extension to parse
    if($reader->getOffset() >= $reader->getSize()){
      return $handshake;
    }

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
}