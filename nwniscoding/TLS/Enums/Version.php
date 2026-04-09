<?php 
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Versions
 * 
 * @package TLS\Enums
 */
enum Version : int{
  case SSL = 0x0300;

  case TLS_10 = 0x0301;

  case TLS_11 = 0x0302;

  case TLS_12 = 0x0303;

  case TLS_13 = 0x0304;

  public function getMajor() : int{
    return ($this->value >> 8) & 0xFF;
  }

  public function getMinor() : int{
    return $this->value & 0xFF;
  }
}