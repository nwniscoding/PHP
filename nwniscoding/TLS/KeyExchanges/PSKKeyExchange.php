<?php
namespace nwniscoding\TLS\KeyExchanges;

use function strlen;
use RuntimeException;

use nwniscoding\TLS\Sessions\ClientSession;

final class PSKKeyExchange extends KeyExchange{
  public function generateClientKeyExchange() : static{
    $session = $this->session;

    if(!($session instanceof ClientSession)){
      throw new RuntimeException('PSK key exchange is only supported for client sessions');
    }

    $identity = $session->getIdentity();

    if($identity === null){
      throw new RuntimeException('PSK key exchange requires an identity to be set for the client session');
    }

    $psk = $session->context->getPSK($identity);
    $length = strlen($psk ?? '');

    $this->sharedSecret = pack('na*na*', $length, str_repeat("\0", $length), $length, $psk);
    
    return $this;
  }

  public function generateServerKeyExchange() : static{
    return $this;
  }
}