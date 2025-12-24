<?php
use nwniscoding\TLS\Enums\CipherEnum;
use nwniscoding\TLS\Enums\RecordEnum;
use nwniscoding\TLS\Enums\VersionEnum;
use nwniscoding\TLS\Extensions\EncryptThenMacExtension;
use nwniscoding\TLS\Extensions\ExtendedMasterSecretExtension;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\ClientKeyExchange;
use nwniscoding\TLS\Handshakes\Finished;
use nwniscoding\TLS\Handshakes\ServerHello;
use nwniscoding\TLS\Record;

require_once 'autoload.php';

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

$psk = hex2bin('1a2b3c4d5e6f7081');
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, 'localhost', 6969);

// Client Hello message
$client_hello = new ClientHello();
$client_hello->setVersion(VersionEnum::TLS_12);
$client_hello->addCiphers(CipherEnum::TLS_PSK_WITH_AES_128_CBC_SHA256);
$client_hello->addExtension(
	new EncryptThenMacExtension(),
	new ExtendedMasterSecretExtension()
);

socket_write($socket, new Record(RecordEnum::HANDSHAKE, VersionEnum::TLS_10, $client_hello));

// Read Server Hello and Server Hello Done
[$server_hello, $server_hello_done] = Record::decode(socket_read($socket, 8192));

$server_hello = $server_hello->getData();
$server_hello_done = $server_hello_done->getData();
$client_key_exchange = new ClientKeyExchange('myidentity');

$handshake_hash = hash(
	'sha256', 
	join('', [
		$client_hello,
		$server_hello,
		$server_hello_done,
		$client_key_exchange
	]), 
	true
);

$psk_len = strlen($psk);
$master_secret = tls_prf(
		'extended master secret', 
		pack('n', $psk_len) . str_repeat("\0", $psk_len) .
		pack('n', $psk_len) . $psk,
		$handshake_hash,
		48
);

$key_expansion = tls_prf(
		'key expansion',
		$master_secret,
		$server_hello->getRandom() . $client_hello->getRandom(),
		128
);

$client = [
	'mac' => substr($key_expansion, 0, 32),
	'key' => substr($key_expansion, 64, 16)
];

$server = [
	'mac' => substr($key_expansion, 32, 32),
	'key' => substr($key_expansion, 80, 16)
];

$finished = new Finished(tls_prf('client finished', $master_secret, $handshake_hash, 12));

$message = new Record(RecordEnum::HANDSHAKE, VersionEnum::TLS_12, $finished);

$seq = pack('N2', 0, 1);
$content_type = "\x16"; // Handshake
$version = "\x03\x03"; // TLS 1.2
$length = pack('n', strlen($finished));

$mac_input = $seq . $content_type . $version . $length . $finished;
$mac = hash_hmac('sha256', $mac_input, $client['mac'], true);

$plaintext = $finished;

$block_size = 16;
$pad_len = $block_size - (strlen($plaintext) % $block_size);
$pad_len = $pad_len === 0 ? $block_size : $pad_len;
$padding = str_repeat(chr($pad_len - 1), $pad_len);
$plaintext .= $padding;
$plaintext .= $mac;

$iv = openssl_random_pseudo_bytes(16);

echo "Finished verify_data: " . bin2hex($finished) . "\n";
echo "MAC key: " . bin2hex($client['mac']) . "\n";
echo "MAC input: " . bin2hex($mac_input) . "\n";
echo "MAC output: " . bin2hex($mac) . "\n";

$ciphertext = openssl_encrypt(
	$plaintext,
	'aes-128-cbc',
	$client['key'],
	OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
	$iv
);

$fragment = $iv . $ciphertext;
$final_record = new Record(RecordEnum::HANDSHAKE, VersionEnum::TLS_12, $fragment);

$client_key_exchange_record = new Record(RecordEnum::HANDSHAKE, VersionEnum::TLS_12, $client_key_exchange);

$change_cipher_spec_record = new Record(RecordEnum::CHANGE_CIPHER, VersionEnum::TLS_12, "\x01");

socket_write($socket, "$client_key_exchange_record$change_cipher_spec_record$final_record");

var_dump(bin2hex($plaintext));
echo "Plaintext length: " . strlen($plaintext) . "\n";
echo "Ciphertext length: " . strlen($ciphertext) . "\n";
echo "Final record (hex): " . bin2hex($final_record) . "\n";

var_dump("client hello: ".bin2hex($client_hello));
var_dump("server hello: ".bin2hex($server_hello));
var_dump("server hello done: ".bin2hex($server_hello_done));
var_dump("client key exchange: ".bin2hex($client_key_exchange));
var_dump("Master secret: " . bin2hex($master_secret));
