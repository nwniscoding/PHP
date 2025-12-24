<?php

function unhex(string $hex): string{
  $hex = str_replace([' ', "\n", "\r", "\t"], '', $hex);
  return hex2bin($hex);
}

function tls_prf(string $label, string $key, string $data, int $length): string{
	$seed = $label . $data;
	$a0 = $seed;
	$output = '';

	while(strlen($output) < $length){
		$a1 = hash_hmac('sha256', $a0, $key, true);
		$p1 = hash_hmac('sha256', $a1 . $seed, $key, true);
		$output .= $p1;
		$a0 = $a1;
	}

	return substr($output, 0, $length);
}