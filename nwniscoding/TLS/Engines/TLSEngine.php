<?php
namespace nwniscoding\TLS\Engines;

use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\ServerHello;

interface TLSEngine{
  public function startAsClient(ClientHello $handshake) : void;

  public function startAsServer(ServerHello $handshake) : void;
}