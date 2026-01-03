<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\ExtensionFactory;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ServerHello extends Handshake{
  private Version $version;

  private string $random;

  private string $session_id;

  private CipherSuite $cipher_suite;

  private array $extensions;

  public function __construct(
    Context $context
  ){
    parent::__construct($context);
    $this->random = openssl_random_pseudo_bytes(32);
  }

  public function setVersion(Version $version): self{
    $this->version = $version;
    return $this;
  }

  public function getversion(): Version{
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

  public function setCipherSuite(CipherSuite $cipher_suite): self{
    $this->cipher_suite = $cipher_suite;
    return $this;
  }

  public function getCipherSuite(): CipherSuite{
    return $this->cipher_suite;
  }

  public function setExtensions(array $extensions): self{
    $this->extensions = $extensions;
    return $this;
  }

  public function getExtensions(): array{
    return $this->extensions;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_HELLO;
  }

  public function encode(): BufferWriter{
    $extension = join('', $this->extensions);

    /**
     * 40 bytes comes from the fixed-size fields in ServerHello:
     * - 2 bytes: version
     * - 32 bytes: random
     * - 1 byte: session id length
     * - 2 bytes: cipher suite
     * - 1 byte: compression method
     * if extensions are present:
     * - 2 bytes: extensions length
     */
    $writer = new BufferWriter(40 + strlen($this->session_id) + strlen($extension));

    $writer->setU16($this->version->value);
    $writer->write($this->random);
    $writer->setU8(strlen($this->session_id));
    $writer->write($this->session_id);
    $writer->setU16($this->cipher_suite->value);
    $writer->setU8(0); // No compression

    if(empty($this->extensions)){
      return $writer;
    }

    $writer->setU16(strlen($extension));
    $writer->write($extension);

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    $handshake->version = Version::from($reader->getU16());
    $handshake->random = $reader->read(32);
    $handshake->session_id = $reader->read($reader->getU8());
    $handshake->cipher_suite = CipherSuite::from($reader->getU16());
    $reader->getU8(); // Ignore compression method

    if($reader->getOffset() >= $reader->getSize()){
      $handshake->extensions = [];
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

  public function __debugInfo(): array{
    return [
      'type' => $this->getType(),
      'version' => $this->version,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suite' => $this->cipher_suite->name,
      'extensions' => $this->extensions
    ];
  }
}