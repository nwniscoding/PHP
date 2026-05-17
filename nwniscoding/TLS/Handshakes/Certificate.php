<?php
namespace nwniscoding\TLS\Handshakes;

use function strlen;

use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Exceptions\CertificateException;
use nwniscoding\TLS\HandshakeContext;
use OpenSSLCertificate;

/**
 * Certificate class represents the Certificate handshake message in the TLS protocol, which is used to exchange certificates between the client and server during the handshake process. 
 */
final readonly class Certificate extends Handshake{
  /**
   * The certificates to be exchanged, which is an array of OpenSSL X.509 certificate resources.
   * @var array<OpenSSLCertificate>
   */
  public array $certificates;

  /**
   * Constructs a new Certificate handshake message.
   * @param array $certificates The certificates to be exchanged, which is an array of OpenSSL X.509 certificate resources.
   * @throws CertificateException If the array contains any non-OpenSSL X.509 certificate resources.
   */
  public function __construct(array $certificates){
    foreach($certificates as $certificate){
      if(!($certificate instanceof OpenSSLCertificate)){
        throw new CertificateException('Invalid certificate: expected OpenSSLCertificate resource, got ' . get_debug_type($certificate));
      }
    }

    $this->certificates = $certificates;
  }

  /**
   * Get the type of handshake message.
   * @return HandshakeType The type of the handshake message, which is HandshakeType::CERTIFICATE.
   */
  public function getType() : HandshakeType{
    return HandshakeType::CERTIFICATE;
  }

  /**
   * Encode the Certificate handshake message to binary format, which consists of a 3-byte length field followed by the DER-encoded certificates. Each certificate is prefixed with a 3-byte length field.
   * @return string The binary representation of the Certificate handshake message.
   * @throws CertificateException If any certificate fails to export or encode properly.
   */
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

  /**
   * Decode a Certificate handshake message from binary format, which consists of a 3-byte length field followed by the DER-encoded certificates. Each certificate is prefixed with a 3-byte length field.
   * @param BufferReader $data The BufferReader to read the Certificate handshake message from.
   * @param HandshakeContext $context The HandshakeContext to use for decoding the handshake message.
   * @return Certificate The decoded Certificate handshake message.
   * @throws CertificateException If any certificate fails to read or decode properly.
   * @throws LengthMismatchException If the total length of the certificates does not match the length specified in the message.
   */
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