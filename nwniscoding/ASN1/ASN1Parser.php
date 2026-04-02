<?php
namespace nwniscoding\ASN1;

use RuntimeException;
use function ord;
use function strlen;

/**
 * Parses ASN.1 encoded data into a tree of ASN1Node objects. 
 * It only supports DER encoding and does not handle indefinite length or complex tag numbers.
 */
final class ASN1Parser{
  /**
   * Parse raw data into ASN1Node structure.
   * @param string $data The raw ASN.1 encoded data.
   * @throws RuntimeException if the data is malformed or cannot be parsed.
   * @return ASN1Node The root ASN1Node representing the parsed structure.
   */
  public static function parse(string $data): ASN1Node{
    // Internal data pointer and size tracking
    $offset = 0;
    $size = strlen($data);

    $node = self::parseNode($data, $offset, $size);

    if($offset !== $size){
      throw new RuntimeException("Unexpected data after parsing ASN.1 structure.");
    }

    return $node;
  }

  /**
   * Parse a single ASN.1 node from the data starting at the given offset all the way to the stated limit.
   * @param string $data The raw ASN.1 encoded data.
   * @param int $offset Reference to the current offset in the data, which will be updated as nodes are parsed.
   * @param int $end The end offset for parsing.
   * @throws RuntimeException if the data is malformed or cannot be parsed.
   * @return ASN1Node The parsed ASN1Node.
   */
  private static function parseNode(string $data, int &$offset, int $end, int $depth = 0): ASN1Node{
    if($depth > 64){
      throw new RuntimeException("ASN.1 nesting limit exceeded.");
    }  

    if($offset >= $end){
      throw new RuntimeException("Unexpected end of data while reading ASN.1 tag.");
    }

    $tag = self::readTag($data, $offset, $end);
    $length = self::readLength($data, $offset, $end);

    if($offset + $length > $end){
      throw new RuntimeException("Unexpected end of data while reading ASN.1 value.");
    }

    if($tag->isConstructed()){
      $node = new ASN1Node($tag);
      $child_end = $offset + $length;

      while($offset < $child_end){
        $node->addChild(self::parseNode($data, $offset, $child_end, $depth + 1));
      }

      if($offset !== $child_end){
        throw new RuntimeException("Unexpected data after parsing ASN.1 sequence.");
      }
    }
    else{
      $node = new ASN1Node($tag, substr($data, $offset, $length));
      $offset += $length;
    }

    return $node;
  }

  /**
   * Read the size of the data at the current offset, handling both short and long form lengths.
   * @param string $data The raw ASN.1 encoded data.
   * @param int $offset Reference to the current offset in the data, which will be updated after reading the length.
   * @param int $size The total size of the data.
   * @throws RuntimeException if the data is malformed or cannot be parsed.
   * @return int The length of the ASN.1 value.
   */
  private static function readLength(string $data, int &$offset, int $size) : int{
    if($offset >= $size){
      throw new RuntimeException("Unexpected end of data while reading ASN.1 length.");
    }

    $byte = ord($data[$offset++]);

    if(($byte & 0x80) === 0){
      return $byte;
    }

    $byte_size = $byte & 0x7F;

    if($byte_size === 0 || $byte_size > 4){
      throw new RuntimeException("Invalid ASN.1 length encoding.");
    }

    if($offset + $byte_size > $size){
      throw new RuntimeException("Unexpected end of data while reading ASN.1 length.");
    }

    $length = 0;

    for($i = 0; $i < $byte_size; $i++){
      $length = ($length << 8) | ord($data[$offset++]);
    }

    return $length;
  }

  /**
   * Read an ASN.1 tag from the data at the current offset.
   * @param string $data The raw ASN.1 encoded data.
   * @param int $offset Reference to the current offset in the data, which will be updated after reading the tag.
   * @param int $size The total size of the data.
   * @throws RuntimeException if the data is malformed or cannot be parsed.
   * @return ASN1Tag The parsed ASN.1 tag.
   */
  private static function readTag(string $data, int &$offset, int $size) : ASN1Tag{
    if($offset >= $size){
      throw new RuntimeException("Unexpected end of data while reading ASN.1 tag.");
    }

    return ASN1Tag::from(ord($data[$offset++]));
  }
}
