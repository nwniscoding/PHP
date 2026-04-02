<?php
namespace nwniscoding\ASN1;

use LogicException;
use function chr;
use function strlen;

/**
 * Represents a node in an ASN.1 structure.
 * Each node has a tag, an optional value and can have child nodes (for constructed types).
 */
final class ASN1Node{
  /**
   * The ASN.1 tag of this node.
   * @var ASN1Tag
   */
  public readonly ASN1Tag $tag;

  /**
   * The value of this node, if it's a primitive type. For constructed types, this will be null and the value is represented by the child nodes.
   * @var ?string
   */
  public readonly ?string $value;

  /**
   * The child nodes of the current node. This is used for constructed type.
   * @var array
   */
  private array $children = [];

  /**
   * Constructs a new ASN1Node with the given tag and optional value.
   * @param ASN1Tag $tag The ASN.1 tag of this node.
   * @param ?string $value The value of this node, if it's a primitive type. For constructed types, this should be null. 
   */
  public function __construct(ASN1Tag $tag, ?string $value = null){
    if($tag->isConstructed() && $value !== null){
      throw new LogicException("Constructed nodes cannot have a value");
    }

    if(!$tag->isConstructed() && $value === null){
      throw new LogicException("Primitive nodes must have a value");
    }

    $this->tag = $tag;
    $this->value = $value;
  }

  /**
   * Get the children of this node. 
   * @return array An array of ASN1Node objects representing the children of this node.
   */
  public function getChildren(): array{
    return $this->children;
  }

  /**
   * Add one or mode child nodes to this node. 
   * @param ASN1Node[] $children The child nodes to add to this node.
   * @throws LogicException If the current node is not a constructed node, since only constructed nodes can have children.
   * @return ASN1Node Returns the current node for method chaining.
   */
  public function addChild(ASN1Node ...$children): self{
    if(!$this->tag->isConstructed()){
      throw new LogicException("Only constructed nodes can have children");
    }

    array_push($this->children, ...$children);

    return $this;
  }

  /**
   * Remove one or more child from this node.
   * @param ASN1Node[] $children The child nodes to remove from this node.
   * @return ASN1Node Returns the current node for method chaining.
   * @throws LogicException If the current node is not a constructed node, since only constructed nodes can have children.
   */
  public function removeChild(ASN1Node ...$children): self{
    if(!$this->tag->isConstructed()){
      throw new LogicException("Only constructed nodes can have children");
    }

    foreach($children as $remove){
      foreach($this->children as $index => $child){
        if($child === $remove){
          unset($this->children[$index]);
          break;
        }
      }
    }

    $this->children = array_values($this->children);
    return $this;
  }

  /**
   * Encode the length of the value according to ASN.1 DER encoding rules.
   * @param int $length The length of the value to encode.
   * @return string The encoded length as a string of bytes.
   */
  private static function getEncodedLength(int $length) : string{
    if($length < 0x80){
      return chr($length);
    }

    $bytes = '';

    while($length > 0){
      $bytes = chr($length & 0xFF) . $bytes;
      $length >>= 8;
    }

    return chr(0x80 | strlen($bytes)) . $bytes;
  }

  /**
   * Encode this node according to ASN.1 DER encoding rules.
   * @return string The encoded string representation of this node.
   */
  public function encode() : string{
    $str = '';

    if($this->tag->isConstructed()){
      foreach($this->children as $child){
        $str .= $child->encode();
      }
    }
    else{
      $str = $this->value ?? '';
    }

    return chr($this->tag->value) . self::getEncodedLength(strlen($str)) . $str;
  }

  /**
   * Convert this node to a string by encoding it according to ASN.1 DER encoding rules.
   * @return string The encoded string representation of this node.
   */
  public function __toString() : string{
    return $this->encode();
  }
}