<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Exceptions\InvalidCipherSuiteException;
use nwniscoding\TLS\Exceptions\InvalidExtensionException;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\HandshakeContext;
use function strlen;
use function count;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Extensions\ExtensionParser;
use nwniscoding\TLS\Extensions\Extension;

final readonly class ClientHello extends Handshake{
  public Version $version;

  public string $random;

  public string $sessionId;

  public array $cipherSuites;

  public array $extensions;

  public function __construct(Version $version, ?string $random, string $sessionId, array $cipherSuites, array $extensions){
    $this->version = $version;

    if($random !== null && strlen($random) !== 32){
      throw new LengthMismatchException('Random must be exactly 32 bytes long');
    }

    $this->random = $random ?? openssl_random_pseudo_bytes(32);
    $this->sessionId = $sessionId;
    
    $this->validateCipherSuites($cipherSuites);
    $this->extensions = $this->normalizeExtensions($extensions);
    $this->cipherSuites = $cipherSuites;
  }

  public function getType() : HandshakeType{
    return HandshakeType::CLIENT_HELLO;
  }

  protected function encode() : string{
    $writer = new BufferWriter();

    $writer->writeUint16($this->version->value);
    $writer->write($this->random);
    $writer->writeUint8(strlen($this->sessionId));
    $writer->write($this->sessionId);

    $writer->writeUint16(count($this->cipherSuites) * 2);
    foreach($this->cipherSuites as $cipherSuite){
      $writer->writeUint16($cipherSuite->value);
    }

    $writer->writeUint16(1 << 8);

    // We can skip extensions if there are none to save some bytes.
    if(!empty($this->extensions)){
      $writer->writeUint16(0);
      $start = $writer->tell();

      foreach($this->extensions as $extension){
        $writer->write($extension);
      }

      $end = $writer->tell();
      $writer->writeUint16($end - $start, $start - 2);
    }

    return $writer->data();
  }

  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    $value = $reader->readUint16();
    $version = Version::tryFrom($value);

    if($version === null){
      throw new TLSEnumException(Version::class, $value, 'ClientHello.version');
    }

    $random = $reader->read(32);
    $sessionId = $reader->read($reader->readUint8());
    $cipherSuites = [];
    $extensions = [];

    $size = $reader->readUint16();

    if($size === 0){
      throw new InvalidCipherSuiteException('At least one cipher suite must be provided');
    }

    if($size % 2 !== 0){
      throw new LengthMismatchException('Invalid ClientHello: Cipher suites length must be a multiple of 2');
    }

    $size /= 2;

    for($i = 0; $i < $size; $i++){
      $value = $reader->readUint16();
      $cipherSuite = CipherSuite::tryFrom($value);

      if($cipherSuite === null){
        throw new TLSEnumException(CipherSuite::class, $value, "ClientHello.cipherSuites[$i]");
      }

      $cipherSuites[] = $cipherSuite;
    }
    
    // Compression length must be 1
    if($reader->readUint8() !== 1){
      throw new LengthMismatchException('Invalid ClientHello: Compression length must be 1');
    }

    // Compression method must be null
    if($reader->readUint8() !== 0){
      throw new TLSException('Invalid ClientHello: Compression method must be null');
    }

    // Check if there are extensions to read
    if(!$reader->EOF()){
      $size = $reader->readUint16();
      $end = $reader->tell() + $size;

      while($reader->tell() < $end){
        $length = 0;
        $extensions[] = ExtensionParser::parse($reader, $length, HandshakeType::CLIENT_HELLO);
      }

      if($reader->tell() !== $end){
        throw new LengthMismatchException('Invalid ClientHello: Extensions length mismatch');
      }
    }

    return new self($version, $random, $sessionId, $cipherSuites, $extensions);
  }

  private function validateCipherSuites(array $cipherSuites) : void{
    if(empty($cipherSuites)){
      throw new InvalidCipherSuiteException('At least one cipher suite must be provided');
    }

    foreach($cipherSuites as $cipherSuite){
      if(!($cipherSuite instanceof CipherSuite)){
        throw new InvalidCipherSuiteException('Invalid cipher suite provided: ' . get_debug_type($cipherSuite));
      }
    }
  }

  private function normalizeExtensions(array $extensions) : array{
    $normalized = [];

    foreach($extensions as $extension){
      if(!($extension instanceof Extension)){
        throw new InvalidExtensionException('Invalid extension provided: ' . get_debug_type($extension));
      }

      if(isset($normalized[$extension->getType()->value])){
        throw new InvalidExtensionException('Duplicate extension type: ' . $extension->getType()->name);
      }

      $normalized[$extension->getType()->value] = $extension;
    }

    return $normalized;
  }
}