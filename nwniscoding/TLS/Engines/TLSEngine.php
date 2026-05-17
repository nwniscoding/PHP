<?php
namespace nwniscoding\TLS\Engines;

use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\Utils\EventEmitter;
use function call_user_func;

use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\ServerHello;
use nwniscoding\TLS\KeySchedules\KeySchedule;
use nwniscoding\TLS\Sessions\Session;

abstract class TLSEngine{
  use EventEmitter;

  protected KeySchedule $keySchedule;

  protected Session $session;

  /**
   * @var array<class-string, array> $handlers
   */
  private array $handlers = [];

  public function __construct(Session $session, KeySchedule $keySchedule){
    $this->session = $session;
    $this->keySchedule = $keySchedule;
  }

  public function handleRecord(Record $record) : void{
    $this->emit(Record::class, $record);

    if($record->type === RecordType::HANDSHAKE){
      $content = $record->content;

      $this->emit(Handshake::class, $record->content);
      
      if($content instanceof Handshake){
        $this->emit($content::class, $content);
      }
    }
  }

  abstract public function startAsClient(ClientHello $handshake) : void;

  abstract public function startAsServer(ServerHello $handshake) : void;
}