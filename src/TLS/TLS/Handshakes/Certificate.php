<?php
namespace TLS\Handshakes;

use OpenSSLCertificate;
use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class Certificate extends Handshake{
  /** @var OpenSSLCertificate[] */
  private array $certificates = [];

  public static function getType(): HandshakeType{
    return HandshakeType::CERTIFICATE;
  }

  public function getCertificate(int $index): OpenSSLCertificate{
    return $this->certificates[$index] ?? null;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    $total_size = 0;

    $writer->setU24(0);

    foreach($this->certificates as $certificate){
      openssl_x509_export($certificate, $output);
      $size = strlen($output);

      $total_size += $size;
      $writer
      ->setU24($size)
      ->write($output);
    }

    $writer->setU24($total_size, 0);
    
    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);
    $total_size = $reader->getU24();

    while($total_size > 0){
      $cert_size = $reader->getU24();
      $cert_data = base64_encode($reader->read($cert_size));
      
      $handshake->certificates[] = openssl_x509_read(
        <<<CERTIFICATE
        -----BEGIN CERTIFICATE-----
        $cert_data
        -----END CERTIFICATE-----
        CERTIFICATE
      );

      $total_size -= 3 + $cert_size;
    }

    return $handshake;
  }
}