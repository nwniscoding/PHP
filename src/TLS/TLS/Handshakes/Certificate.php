<?php
namespace TLS\Handshakes;

use OpenSSLCertificate;
use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class Certificate extends Handshake{
  private array $certificates = [];

  public function setCertificates(OpenSSLCertificate ...$certificates): self{
    $this->certificates = $certificates;
    return $this;
  }

  public function getCertificates(): array{
    return $this->certificates;
  }

  public function encode(): BufferWriter{
    $total_len = 0;
    $writer = new BufferWriter;
    
    $writer->setU24(0);

    foreach($this->certificates as $certificate){
      openssl_x509_export($certificate, $cert_data);

      $cert_data = base64_decode(preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $cert_data));

      $writer->setU24($total_len += strlen($cert_data));
      $writer->write($cert_data);
    }

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);
    $total_len = $reader->getU24();

    while($reader->getOffset() < $reader->getSize()){
      $cert_data = $reader->read($reader->getU24());

      $cert_data = rtrim(chunk_split(base64_encode($cert_data), 64, "\n"));

      $handshake->certificates[] = openssl_x509_read(<<<Certificate
        -----BEGIN CERTIFICATE-----
        $cert_data
        -----END CERTIFICATE-----
        Certificate);
    }

    return $handshake;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::CERTIFICATE;
  }
}