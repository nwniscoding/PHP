<?php
namespace nwniscoding\TLS\KeyExchanges;

use nwniscoding\TLS\Params\DHEParam;
use nwniscoding\TLS\Sessions\ClientSession;
use RuntimeException;

final class DHEKeyExchange extends KeyExchange{
  public function generateClientKeyExchange() : static{
    $session = $this->session;
    $context = $session->handshakeContext;
    $param = $context->getServerKeyExchange()->keyExchangeParam;
    $info = $context->getCipherInfo();

    if(!($session instanceof ClientSession)){
      throw new RuntimeException
      ("Expected ClientSession for DHE key exchange");
    }

    if(!($param instanceof DHEParam)){
      throw new RuntimeException("Expected DHE parameters in ServerKeyExchange");
    }

    $serverKey = $param->publicKey;
    $clientKey = openssl_pkey_new([
      'private_key_type' => OPENSSL_KEYTYPE_DH,
      'dh' => [
        'p' => $param->prime,
        'g' => $param->generator,
      ],
    ]);

    $otherSecret = openssl_dh_compute_key($serverKey, $clientKey);

    if($otherSecret === false){
      throw new RuntimeException("Failed to compute shared secret");
    }

    $this->param = new DHEParam(openssl_pkey_get_details($clientKey)['dh']['pub_key']);
    
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