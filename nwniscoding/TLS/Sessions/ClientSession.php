<?php
namespace nwniscoding\TLS\Sessions;

use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\Extensions\SignatureAlgorithms;
use nwniscoding\TLS\Extensions\SupportedGroups;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\TLSContext;
use Socket;

final class ClientSession extends Session{
  private ?string $identity;
  
  public function __construct(Socket $socket, TLSContext $context, ?string $identity = null){
    parent::__construct($socket, $context);

    $this->identity = $identity;
  }

  public function negotiate(array $extensions = []) : void{

    $clientHello = new ClientHello(
      Version::TLS_12,
      null,
      '',
      $this->context->getCipherSuites(),
      [
        ...$extensions,
        new SupportedGroups($this->context->getGroups()),
        new SignatureAlgorithms($this->context->getSignatures())
      ]
    );

    $this->engine->startAsClient($clientHello);
  }

  public function getIdentity() : ?string{
    return $this->identity;
  }

  public function sendData(string $data): void{
    $cipher = $this->clientCipher;
    
    if($cipher === null){
      throw new TLSException("No cipher available for encrypting application data");
    }

    $this->send(Record::applicationData($this->context->version, $cipher->encrypt($this->nextClientSequence(), RecordType::APPLICATION_DATA, $this->context->version, $data)));
  }
}