<?php
namespace TLS;

use Exception;
use Socket;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ServerHello;

class Client{
  private Socket $socket;

  private Context $context;

  private Config $config;

  private string $host;

  private int $port;

  public function __construct(string $host, int $port, Config $config){
    $this->config = $config;
    $this->context = new Context($config->getVersion());
    $this->host = $host;
    $this->port = $port;
  }

  public function connect(): never{
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

    if(!$socket){
      throw new Exception("Failed to create socket: " . socket_strerror(socket_last_error()));
    }

    if(!socket_connect($socket, $this->host, $this->port)){
      throw new Exception("Failed to connect to {$this->host}:{$this->port}: " . socket_strerror(socket_last_error($socket)));
    }

    $this->socket = $socket;
    $sockets = [$this->socket];
    $null = null;

    $client_hello = new ClientHello();

    $client_hello->setVersion($this->config->getVersion());
    $client_hello->setCipherSuites(...$this->config->getCipherSuites());
    $client_hello->setExtensions(...array_values($this->config->getExtensions()));

    socket_write($this->socket, new Record(RecordType::HANDSHAKE, Version::TLS_10, $client_hello));
    
    $this->context->setHandshake($client_hello);


    while(true){
      $read = $sockets;

      if(socket_select($read, $null, $null, 1) === false){
        throw new Exception("Socket select failed: " . socket_strerror(socket_last_error($this->socket)));
      }

      foreach($read as $socket){
        $data = socket_read($socket, 1024 * 8);
        
        foreach(Record::parseRecord($data) as $record){
          if($record->getType() === RecordType::HANDSHAKE){
            $this->context->setHandshake($record->getData());
          }

          if($this->context->hasHandshake(HandshakeType::SERVER_HELLO)){
            
          }
        }
      }
    }
  }
}