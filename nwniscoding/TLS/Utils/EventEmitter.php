<?php
namespace nwniscoding\TLS\Utils;

trait EventEmitter{
  private array $listeners = [];

  public function on(string $event, callable | array $listener) : void{
    if(!isset($this->listeners[$event])){
      $this->listeners[$event] = [];
    }

    $this->listeners[$event][] = $listener;
  }

  public function emit(string $event, mixed ...$args) : void{
    if(isset($this->listeners[$event])){
      foreach($this->listeners[$event] as $listener){
        $listener(...$args);
      }
    }
  }
}