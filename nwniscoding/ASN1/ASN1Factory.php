<?php
namespace nwniscoding\ASN1;

use InvalidArgumentException;
use function chr;
use function ord;
use function count;
/**
 * Factory class for creating ASN1Node instances. 
 * This class provides a simple interface for creating ASN1Node objects with specified tags and values. 
 */
final class ASN1Factory{
  /**
   * Create a BOOLEAN ASN1Node with the given value.
   * @param bool $value The boolean value to encode.
   * @return ASN1Node The created ASN1Node representing the BOOLEAN value.
   */
  public static function boolean(bool $value) : ASN1Node{
    return new ASN1Node(ASN1Tag::BOOLEAN, $value ? "\xFF" : "\0");
  }

  /**
   * Create an INTEGER ASN1Node with the given value. Only non-negative integers are supported.
   * @param int $value The integer value to encode. Must be non-negative.
   * @throws InvalidArgumentException if the value is negative.
   * @return ASN1Node The created ASN1Node representing the INTEGER value.
   */
  public static function integer(int $value) : ASN1Node{
    return new ASN1Node(ASN1Tag::INTEGER, self::encodeInteger($value));
  }

  /**
   * Create a BIT STRING ASN1Node with the given value. The value will be prefixed with a byte indicating the number of unused bits (set to 0).
   * @param string $value The binary string to encode as a BIT STRING. It will be prefixed with a byte indicating the number of unused bits (set to 0).
   * @return ASN1Node The created ASN1Node representing the BIT STRING value.
   */
  public static function bitString(string $value) : ASN1Node{
    return new ASN1Node(ASN1Tag::BIT_STRING, "\0$value");
  }

  /**
   * Create an OCTET STRING ASN1Node with the given value.
   * @param string $value The binary string to encode as an OCTET STRING.
   * @return ASN1Node The created ASN1Node representing the OCTET STRING value.
   */
  public static function octetString(string $value) : ASN1Node{
    return new ASN1Node(ASN1Tag::OCTET_STRING, $value);
  }

  /**
   * Create a NULL ASN1Node.
   * @return ASN1Node The created ASN1Node representing the NULL value.
   */
  public static function null() : ASN1Node{
    return new ASN1Node(ASN1Tag::NULL, '');
  }

  /**
   * Create an OBJECT IDENTIFIER ASN1Node with the given components. The components should be an array of integers representing the OID.
   * @param array $components An array of integers representing the OID components. The first two components will be encoded according to ASN.1 rules (first * 40 + second).
   * @throws InvalidArgumentException if the components array has fewer than 2 elements.
   * @return ASN1Node The created ASN1Node representing the OBJECT IDENTIFIER value.
   */
  public static function objectIdentifier(array $components) : ASN1Node{
    return new ASN1Node(ASN1Tag::OBJECT_IDENTIFIER, self::encodeOID($components));
  }

  /**
   * Create a SEQUENCE ASN1Node containing the given child nodes. The child nodes will be added as children of the SEQUENCE node.
   * @param ASN1Node ...$children A variable number of ASN1Node instances to include in the SEQUENCE.
   * @return ASN1Node The created ASN1Node representing the SEQUENCE value.
   */
  public static function sequence(ASN1Node ...$children) : ASN1Node{
    $node = new ASN1Node(ASN1Tag::SEQUENCE);

    foreach($children as $child){
      $node->addChild($child);
    }

    return $node;
  }

  /**
   * Encode a non-negative integer into its ASN.1 DER representation. This method does not support negative integers or integers larger than PHP's integer limit.
   * @param int $value The non-negative integer to encode. Must be less than or equal to PHP's maximum integer value.
   * @throws InvalidArgumentException if the value is negative.
   * @return string The ASN.1 DER encoded representation of the integer, as a binary string.
   */
  private static function encodeInteger(int $value) : string{
    if($value < 0){
      throw new InvalidArgumentException("Negative integers are not supported.");
    }

    if($value === 0){
      return "\0";
    }

    $bytes = '';

    while($value > 0){
      $bytes = chr($value & 0xFF) . $bytes;
      $value >>= 8;
    }

    if(ord($bytes[0]) & 0x80){
      $bytes = "\0$bytes";
    }

    return $bytes;
  }

  /**
   * Encode an OID given its components.
   * @param array $components An array of integers representing the OID components.
   * @throws InvalidArgumentException if the components array has fewer than 2 elements.
   * @return string The ASN.1 DER encoded representation of the OID, as a binary string.
   */
  private static function encodeOID(array $components) : string{
    if(count($components) < 2){
      throw new InvalidArgumentException("OID must have at least two components.");
    }

    $result = chr($components[0] * 40 + $components[1]);

    for($i = 2, $size = count($components); $i < $size; $i++){
      $value = $components[$i];
      $bytes = [];

      do{
        $bytes[] = $value & 0x7F;
        $value >>= 7;
      }
      while($value > 0);

      for($j = count($bytes) - 1; $j >= 0; $j--){
        $byte = $bytes[$j];

        if($j !== 0){
          $byte |= 0x80;
        }

        $result .= chr($byte);
      }
    }

    return $result;
  }
}