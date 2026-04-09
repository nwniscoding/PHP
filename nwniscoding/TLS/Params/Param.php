<?php
namespace nwniscoding\TLS\Params;

interface Param{
  public const int CLIENT = 0;

  public const int SERVER = 1;

  public function __tostring() : string;
}