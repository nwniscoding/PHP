<?php
namespace TLS\Handshakes;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use TLS\Enums\HandshakeType;
use TLS\MessageInterface;
use TLS\Utils\BufferReader;

class Certificate extends Handshake{
  private array $certificates;

  public function __construct(OpenSSLCertificate ...$certificates){
    parent::__construct(HandshakeType::CERTIFICATE);
    $this->certificates = $certificates;
  }
  
  public function encode(): string{
    $total_size = 0;
    $data = [];

    foreach($this->certificates as $cert){
      openssl_x509_export($cert, $cert_data);

      $cert_data = base64_decode(preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $cert_data));
      $cert_size = strlen($cert_data);
      $data[] = pack('nCa*', $cert_size >> 8, $cert_size & 0xff, $cert_data);
      
      $total_size += strlen($cert_data) + 3;
    }

    return pack('nCa*', $total_size >> 8, $total_size & 0xff, implode('', $data));
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $total_size = $buffer->getU16() << 8 | $buffer->getU8();
    $certificates = [];

    while($buffer->getOffset() < $total_size){
      $cert_size = $buffer->getU16() << 8 | $buffer->getU8();
      $cert_data = $buffer->read($cert_size);

      $cert_data = rtrim(chunk_split(base64_encode($cert_data), 64, "\n"));
      

      $certificates[] = openssl_x509_read(<<<Certificate
        -----BEGIN CERTIFICATE-----
        $cert_data
        -----END CERTIFICATE-----
        Certificate);
    }

    return new self(...$certificates);
  }

  public function getCertificates(): array{
    return $this->certificates;
  }

  public function setCertificates(OpenSSLCertificate ...$certificates): void{
    $this->certificates = $certificates;
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => 'Certificate',
      'certificates' => array_map(fn($cert) => openssl_x509_parse($cert), $this->certificates)
    ];
  }
}