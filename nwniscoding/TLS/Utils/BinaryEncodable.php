<?php
namespace nwniscoding\TLS\Utils;

interface BinaryEncodable{
  public function toBinary() : string;
}