<?php
namespace nwniscoding\ASN1;

/**
 * Represents an ASN.1 tag, which consists of a tag number and a constructed flag.
 */
enum ASN1Tag: int{
  case BOOLEAN = 0x01;
  
  case INTEGER = 0x02;
  
  case BIT_STRING = 0x03;
  
  case OCTET_STRING = 0x04;
  
  case NULL = 0x05;
  
  case OBJECT_IDENTIFIER = 0x06;
  
  case SEQUENCE = 0x30;

  /**
   * Check if the tag is constructed (i.e., if it can contain child nodes).
   * @return bool True if the tag is constructed, false otherwise.
   */
  public function isConstructed(): bool{
    return ($this->value & 0x20) !== 0;
  }
}