<?php
namespace nwniscoding\TLS\KeyExchanges;

use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\Sessions\Session;
use SessionHandler;

final class KeyExchangeFactory{
  public static function create(Session $session) : KeyExchange{
    $context = $session->handshakeContext;
    $info = $context->getCipherInfo();
    $keyExchange = match($info->keyExchange){
      'rsa' => new RSAKeyExchange($session),
      'dhe' => new DHEKeyExchange($session),
      'ecdhe' => new ECDHEKeyExchange($session),
      'psk' => new PSKKeyExchange($session),
    };

    if($session instanceof ClientSession){
      return $keyExchange->generateClientKeyExchange();
    }
    else{
      return $keyExchange->generateServerKeyExchange();
    }
  }
}