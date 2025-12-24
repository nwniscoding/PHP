<?php
use nwniscoding\TLS\Enums\RecordEnum;
use nwniscoding\TLS\Enums\VersionEnum;
use nwniscoding\TLS\Record;

require_once 'autoload.php';

// This test works for TLS 1.2 with PSK and Extended Master Secret extension
$encrypted_handshake = "e7688e990b21be0f2dd6752aebbd933ead6796f9fa7aa515290537ec1bf4b449f8937075945ed6c9df66bfc7e531d60f783a433e0d476a123af73066fcc92806c3ef0b8336d124b982fe655a47e93b50";

$encrypted_server_handshake = 
"7fef0c8d5a240f557b73faa33c3afcec2849d5ef5a4164db0bd490362c9918b52576452c2002622aa12b36c2bdaf19f0c1f4a747bdf9190386eec92de5e5ac70eae078662201cc6d906d2e72ab0e8ca5";


// client hello
$client_hello = "0100006603034315bed8223946651fb201e8e94070b264fcb188caac5159ccc271546bc0c55300000200ae0100003bff010001000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602";

// server hello
$server_hello = "0200005503030b87caaa8cc99a14b777aa51d74df4d187800e48ed4ddb24444f574e47524401204bbc0c375e03e2690f54c5d13638534bcb3943a6ec907a858e7b8d602b2366d000ae00000dff010001000016000000170000";

// server hello done
$server_hello_done = "0e000000";

// client key
$client_key_exchange = "1000000c000a6d796964656e74697479";

$client_hello = hex2bin($client_hello);
$server_hello = hex2bin($server_hello);
$server_hello_done = hex2bin($server_hello_done);
$client_key_exchange = hex2bin($client_key_exchange);
$actual_master_secret = hex2bin("85522600CDFC7EA32608400243D9CB85EFAFAEE33FE506EBAF502DB1BC52A375CDBD0E44F2C6C311ECAB403EEDB1B007");
$psk = hex2bin('1a2b3c4d5e6f7081');

$hash = hash(
    'sha256',
    $client_hello . 
    $server_hello . 
    $server_hello_done . $client_key_exchange,
    true
);

$seed = "extended master secret" . $hash;

// pre-master secret for PSK
$psk_len = strlen($psk);
$pre_master_secret = pack('n', $psk_len) . str_repeat("\0", $psk_len) . pack('n', $psk_len) . $psk;

// Deriving master secret
$a0 = $seed;
$a1 = hash_hmac('sha256', $a0, $pre_master_secret, true);
$a2 = hash_hmac('sha256', $a1, $pre_master_secret, true);
$p1 = hash_hmac('sha256', $a1 . $seed, $pre_master_secret, true);
$p2 = hash_hmac('sha256', $a2 . $seed, $pre_master_secret, true);
$master_secret = substr($p1 . $p2, 0, 48);



var_dump(bin2hex(tls_prf('extended master secret', $pre_master_secret, $hash, 48)));
var_dump('master secret: ' . bin2hex($master_secret));

$encrypted_handshake = hex2bin($encrypted_handshake);
$encrypted_server_handshake = hex2bin($encrypted_server_handshake);

// The below is the server-random + client-random from the hellos
$seed = "key expansion" . 
hex2bin("0b87caaa8cc99a14b777aa51d74df4d187800e48ed4ddb24444f574e475244014315bed8223946651fb201e8e94070b264fcb188caac5159ccc271546bc0c553");

$a0 = $seed;
$a1 = hash_hmac('sha256', $a0, $master_secret, true);
$a2 = hash_hmac('sha256', $a1, $master_secret, true);
$a3 = hash_hmac('sha256', $a2, $master_secret, true);
$a4 = hash_hmac('sha256', $a3, $master_secret, true);

$p1 = hash_hmac('sha256', $a1 . $seed, $master_secret, true);
$p2 = hash_hmac('sha256', $a2 . $seed, $master_secret, true);
$p3 = hash_hmac('sha256', $a3 . $seed, $master_secret, true);
$p4 = hash_hmac('sha256', $a4 . $seed, $master_secret, true);

$key_block = $p1 . $p2 . $p3 . $p4;

$offset = 0;
$client_mac_key = substr($key_block, $offset, 32); $offset += 32;
$server_mac_key = substr($key_block, $offset, 32); $offset += 32;

$client_key = substr($key_block, $offset, 16); $offset += 16;
$server_key = substr($key_block, $offset, 16); $offset += 16;

$client_iv = substr($key_block, $offset, 16); $offset += 16;
$server_iv = substr($key_block, $offset, 16); $offset += 16;

$explicit_iv = substr($encrypted_handshake, 0, 16);
$ciphertext = substr($encrypted_handshake, 16);

$plaintext = openssl_decrypt(
    $ciphertext,
    'aes-128-cbc',
    $client_key,
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    $explicit_iv
);

// The padding for openssl is included after the finished message
$handshake = substr($plaintext, 0, 16);
$padding = substr($plaintext, 16, 16);
$mac = substr($plaintext, 32);

// Finished message 
$verify_data = substr($handshake, 4, 12);

$seed = "client finished" . $hash;
$a0 = $seed;
$a1 = hash_hmac('sha256', $a0, $master_secret, true);
$p1 = hash_hmac('sha256', $a1 . $seed, $master_secret, true);

// Verify data comparison
// var_dump(bin2hex($verify_data));
// var_dump(bin2hex($p1));

// MAC

var_dump(bin2hex($plaintext));