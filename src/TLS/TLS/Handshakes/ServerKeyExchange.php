<?php
namespace TLS\Handshakes;

use Exception;
use OpenSSLAsymmetricKey;
use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Enums\SignatureAlgorithm;
use TLS\Enums\SupportedGroup;
use TLS\Params\ECDHEKeyExchangeParam;
use TLS\Params\ECDHEParam;
use TLS\Params\Param;
use TLS\Utils\ASN1;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class ServerKeyExchange extends Handshake{
  private ?Param $param;
  private ?SignatureAlgorithm $signature_algorithm;

  private ?string $signature;

  private ?string $identity;

  public function __construct(Context $context){
    parent::__construct($context);
  }

  public function setParam(Param $param): self{
    $this->param = $param;
    return $this;
  }

  public function getParam(): Param{
    return $this->param;
  }

  public function setSignatureAlgorithm(SignatureAlgorithm $signature_algorithm): self{
    $this->signature_algorithm = $signature_algorithm;
    return $this;
  }

  public function getSignatureAlgorithm(): ?SignatureAlgorithm{
    return $this->signature_algorithm;
  }

  public function getSignatureHash(): ?int{
    $hash = $this->signature_algorithm->value >> 8;

    return match($hash){
      0x4 => OPENSSL_ALGO_SHA256,
      0x5 => OPENSSL_ALGO_SHA384,
      0x6 => OPENSSL_ALGO_SHA512,
      default => null,
    };
  }

  public function setSignature(string $signature): self{
    $this->signature = $signature;
    return $this;
  }

  public function getSignature(): ?string{
    return $this->signature;
  }

  public function setPSKIdentity(string $identity): self{
    $this->identity = $identity;
    return $this;
  }

  public function getPSKIdentity(): ?string{
    return $this->identity;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    /** @var ServerHello */
    $server_hello = $this->context->getHandshake(HandshakeType::SERVER_HELLO);

    $metadata = $server_hello->getCipherSuite()->metadata();

    if($metadata['authentication'] === 'PSK'){
      $writer
      ->setU16(strlen($this->identity))
      ->write($this->identity);
    }

    switch($metadata['key_exchange']){
      case 'ECDHE' :
        $writer
        ->write($this->param)
        ->setU16($this->signature_algorithm->value)
        ->setU16(strlen($this->signature))
        ->write($this->signature)
        ;

      break;
    }

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    /** @var ServerHello */
    $server_hello = $context->getHandshake(HandshakeType::SERVER_HELLO);
    $handshake = new self($context);

    $metadata = $server_hello->getCipherSuite()->metadata();

    $handshake->psk = $metadata['authentication'] === 'PSK' ? $reader->read($reader->getU16()) : null;

    switch($metadata['key_exchange']){
      case 'ECDHE' :
        if($reader->getU8() !== 3)
          throw new Exception("Unsupported ECDHE curve type");
        
        $group = SupportedGroup::from($reader->getU16());
        $public_key = self::convertPubKeyToPEM(
          $reader->read($reader->getU8()), 
          $group
        );

        $handshake->param = new ECDHEParam(
          $group,
          $public_key
        );

        $handshake->signature_algorithm = SignatureAlgorithm::from($reader->getU16());
        $handshake->signature = $reader->read($reader->getU16());
      break;
    }

    return $handshake;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_KEY_EXCHANGE;
  }

  private static function convertPubKeyToPEM(string $raw_key, SupportedGroup $group): OpenSSLAsymmetricKey|bool{
    $spki = ASN1::seq(
      ASN1::seq(
        ASN1::getOIDString([1, 2, 840, 10045, 2, 1]),
        ASN1::getOIDString(SupportedGroup::getOID($group)) 
      ),
      ASN1::bit($raw_key)
    );

    $pem = "-----BEGIN PUBLIC KEY-----\n";
    $pem .= chunk_split(base64_encode($spki), 64, "\n");
    $pem .= "-----END PUBLIC KEY-----\n";

    return openssl_pkey_get_public($pem);
  }
}