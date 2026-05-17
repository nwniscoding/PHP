<?php
namespace nwniscoding\TLS\KeyExchanges;

use nwniscoding\TLS\Params\RSAParam;
use RuntimeException;

final class RSAKeyExchange extends KeyExchange{
  public function generateClientKeyExchange() : static{
    $session = $this->session;
    $context = $session->handshakeContext;
    $certificate = $context->getCertificate();
    $info = $context->getCipherInfo();

    if($certificate === null){
      throw new RuntimeException("No certificate found in handshake context for RSA key exchange");
    }

    $otherSecret = random_bytes(48);
    $otherSecret[0] = chr(0x03);
    $otherSecret[1] = chr(0x03);

    openssl_public_encrypt($otherSecret, $encryptedSecret, $certificate->certificates[0], OPENSSL_PKCS1_PADDING);
    $this->param = new RSAParam($encryptedSecret);
    
    if($info->authentication === 'psk'){
      $pskSecret = $session->context->getPSK($session->getIdentity());

      if($pskSecret === null){
        throw new RuntimeException("No PSK secret found for identity {$session->getIdentity()}");
      }

      $otherSecret = pack('na*na*', strlen($otherSecret), $otherSecret, strlen($pskSecret), $pskSecret);
    }

    $this->sharedSecret = $otherSecret;

    return $this;
  }

  public function generateServerKeyExchange() : static{
    return $this;
  }
}