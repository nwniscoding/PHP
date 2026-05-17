<?php
namespace nwniscoding\TLS\KeyExchanges;

use nwniscoding\TLS\Params\ECDHEParam;
use nwniscoding\TLS\Sessions\ClientSession;
use RuntimeException;

final class ECDHEKeyExchange extends KeyExchange{
  public function generateClientKeyExchange() : static{
    $session = $this->session;
    $context = $session->handshakeContext;
    $param = $context->getServerKeyExchange()->keyExchangeParam;
    $info = $context->getCipherInfo();

    if(!($session instanceof ClientSession)){
      throw new RuntimeException("Expected ClientSession for ECDHE key exchange");
    }

    if(!($param instanceof ECDHEParam)){
      throw new RuntimeException("Expected ECDHE parameters in ServerKeyExchange");
    }

    $serverKey = $param->curveId->wrapPublicKey($param->publicKey);
    $clientKey = $param->curveId->createPrivateKey();
    $otherSecret = openssl_pkey_derive($serverKey, $clientKey);

    if($otherSecret === false){
      throw new RuntimeException("Failed to derive shared secret");
    }

    $this->param = new ECDHEParam($param->curveId->exportPublicKey($clientKey));

    if($info->authentication === 'psk'){
      $pskSecret = $session->context->getPSK($session->getIdentity());

      if($pskSecret === null){
        throw new RuntimeException("No PSK secret found for identity {$session->getIdentity()}");
      }

      $otherSecret ??= str_repeat("\0", strlen($pskSecret));
      $otherSecret = pack('na*na*', strlen($otherSecret), $otherSecret, strlen($pskSecret), $pskSecret);
    }

    $this->sharedSecret = $otherSecret;
    
    return $this;
  }

  public function generateServerKeyExchange() : static{
    return $this;
  }
}