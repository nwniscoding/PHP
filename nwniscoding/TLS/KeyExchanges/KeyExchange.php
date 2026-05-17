<?php
namespace nwniscoding\TLS\KeyExchanges;

use nwniscoding\TLS\HandshakeContext;
use nwniscoding\TLS\Params\Param;
use nwniscoding\TLS\Sessions\Session;

abstract class KeyExchange{
  protected Session $session;

  protected ?Param $param = null;

  protected ?string $sharedSecret = null;

  public function __construct(Session $session){
    $this->session = $session;
  }

  abstract public function generateClientKeyExchange() : static;

  abstract public function generateServerKeyExchange() : static;

  public function getParam() : ?Param{
    return $this->param;
  }

  public function getSharedSecret() : ?string{
    return $this->sharedSecret;
  }
}