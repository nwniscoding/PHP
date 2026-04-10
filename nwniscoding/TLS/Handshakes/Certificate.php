<?php
namespace nwniscoding\TLS\Handshakes;

use function strlen;

use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Exceptions\CertificateException;
use nwniscoding\TLS\HandshakeContext;

final readonly class Certificate extends Handshake{
  public array $certificates;

  public function __construct(array $certificates){
    $this->certificates = $certificates;
  }

  public function getType() : HandshakeType{
    return HandshakeType::CERTIFICATE;
  }

  public function encode() : string{
    $writer = new BufferWriter();
    $size = 0;
    
    $writer->writeUint24(0);

    foreach($this->certificates as $certificate){
      if(openssl_x509_export($certificate, $output) === false){
        throw new CertificateException('Failed to export certificate: ' . openssl_error_string());
      }

      $output = explode("\n", trim($output));
      array_shift($output);
      array_pop($output);

      $data = base64_decode(join('', $output));
      $length = strlen($data);

      $writer->writeUint24($length);
      $writer->write($data);

      $size += 3 + $length;
    }

    $writer->seek(0);
    $writer->writeUint24($size);

    return $writer->data();
  }

  public static function decode(BufferReader $data, HandshakeContext $context) : self{
    $certificates = [];
    $size = $data->readUint24();
    $end = $data->tell() + $size;

    while($data->tell() < $end){
      $cert_size = $data->readUint24();
      $base64 = base64_encode($data->read($cert_size));
      $certificate = openssl_x509_read(
        <<<CERT
        -----BEGIN CERTIFICATE-----
        $base64
        -----END CERTIFICATE-----
        CERT
      );

      if($certificate === false){
        throw new CertificateException("Failed to read certificate: " . openssl_error_string());
      }

      $certificates[] = $certificate;
    }

    if($data->tell() !== $end){
      throw new LengthMismatchException("Invalid certificate length: expected $size bytes, got " . ($data->tell() - ($end - $size)));
    }

    return new self($certificates);
  }
}