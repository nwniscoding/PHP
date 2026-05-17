<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Exceptions\InvalidExtensionException;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use nwniscoding\TLS\Extensions\Extension;
use nwniscoding\TLS\Extensions\ExtensionParser;
use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\HandshakeContext;

final readonly class ServerHello extends Handshake{
  public Version $version;

  public string $random;

  public string $sessionId;

  public CipherSuite $cipherSuite;

  public array $extensions;

  public function __construct(Version $version, ?string $random, string $sessionId, CipherSuite $cipherSuite, array $extensions){
    $this->version = $version;

    if($random !== null && strlen($random) !== 32){
      throw new LengthMismatchException('Random must be exactly 32 bytes long');
    }

    $this->random = $random ?? openssl_random_pseudo_bytes(32);
    $this->sessionId = $sessionId;
    $this->cipherSuite = $cipherSuite;
    $this->extensions = $this->normalizeExtensions($extensions);
  }
  
  public function getType() : HandshakeType{
    return HandshakeType::SERVER_HELLO;
  }

  protected function encode() : string{
    $writer = new BufferWriter();
    $writer->writeUint16($this->version->value);
    $writer->write($this->random);
    $writer->writeUint8(strlen($this->sessionId));
    $writer->write($this->sessionId);
    $writer->writeUint16($this->cipherSuite->value);
    $writer->writeUint8(0);

    if(!empty($this->extensions)){
      $writer->writeUint16(0);
      $start = $writer->tell();

      foreach($this->extensions as $extension){
        $writer->write($extension->toBinary(HandshakeType::SERVER_HELLO));
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
      throw new TLSEnumException(Version::class, $value, 'ServerHello.version');
    }

    $random = $reader->read(32);
    $sessionId = $reader->read($reader->readUint8());

    $value = $reader->readUint16();
    $cipherSuite = CipherSuite::tryFrom($value);

    if($cipherSuite === null){
      throw new TLSEnumException(CipherSuite::class, $value, 'ServerHello.cipherSuite');
    }

    $extensions = [];

    $reader->seek(1, SEEK_CUR);

    if(!$reader->EOF()){
      $size = $reader->readUint16();
      $end = $reader->tell() + $size;

      while($reader->tell() < $end){
        $length = 0;
        $extensions[] = ExtensionParser::parse($reader, $length, HandshakeType::SERVER_HELLO);
      }

      if($reader->tell() !== $end){
        throw new LengthMismatchException('Invalid ServerHello: Extensions length mismatch');
      }
    }

    return new self($version, $random, $sessionId, $cipherSuite, $extensions);
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