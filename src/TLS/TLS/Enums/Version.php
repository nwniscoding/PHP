<?php 
namespace TLS\Enums;

/**
 * Enumeration of TLS Versions
 * 
 * @package Enums
 */
enum Version : int{
  case SSL = 0x0300;

  case TLS_10 = 0x0301;

  case TLS_11 = 0x0302;

  case TLS_12 = 0x0303;

  case TLS_13 = 0x0304;
}