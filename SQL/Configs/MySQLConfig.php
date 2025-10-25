<?php
namespace SQL\Configs;

use Closure;
use SensitiveParameter;
use SensitiveParameterValue;
use SQL\ConfigInterface;

/**
 * Configuration settings for connecting to a MySQL database.
 */
final class MySQLConfig implements ConfigInterface{
	/**
	 * The hostname or IP address of the MySQL server.
	 * @var string
	 */
	private string $host;

	/**
	 * The port number to use for the MySQL connection.
	 * @var int
	 */
	private int $port;

	/**
	 * The username to use for the MySQL connection.
	 * @var SensitiveParameterValue
	 */
	private SensitiveParameterValue $username;

	/**
	 * The password to use for the MySQL connection.
	 * @var SensitiveParameterValue
	 */
	private SensitiveParameterValue $password;

	/**
	 * The name of the database to connect to.
	 * @var string
	 */
	private string $database;

	/**
	 * The character set to use for the MySQL connection.
	 * @var string
	 */
	private string $charset;

	/**
	 * The Unix socket to use for the MySQL connection, if applicable.
	 * @var string|null
	 */
	private ?string $unix_socket;

	/**
	 * Constructor to initialize MySQL configuration settings.
	 * @param string $host The hostname or IP address of the MySQL server.
	 * @param int $port The port number to use for the MySQL connection.
	 * @param string $username The username to use for the MySQL connection.
	 * @param string $password The password to use for the MySQL connection.
	 * @param string $database The name of the database to connect to.
	 * @param string $charset The character set to use for the MySQL connection.
	 * @param mixed $unix_socket The Unix socket to use for the MySQL connection, if applicable.
	 */
	public function __construct(
		string $host,
		int $port,
		#[SensitiveParameter] string $username,
		#[SensitiveParameter] string $password,
		string $database,
		string $charset = "utf8mb4",
		?string $unix_socket = null
	){
		$this->host = $host;
		$this->port = $port;
		$this->username = new SensitiveParameterValue($username);
		$this->password = new SensitiveParameterValue($password);
		$this->database = $database;
		$this->charset = $charset;
		$this->unix_socket = $unix_socket;
	}

	/**
	 * Get the type of database configuration.
	 *
	 * @return string The type of database (e.g., "mysql").
	 */
	public function getType(): string{
		return "mysql";
	}

	/**
	 * Apply the configuration values to a given function.
	 *
	 * @param callable(array<string, mixed>): bool $fn The function to apply the credentials to.
	 * @return bool True on success, false on failure.
	 */
	public function apply(Closure|array $fn): void{
		$fn([
			"username" => $this->username->getValue(),
			"password" => $this->password->getValue(),
			"host" => $this->host,
			"port" => $this->port,
			"database" => $this->database,
			"charset" => $this->charset,
			"unix_socket" => $this->unix_socket
		]);
	}

	/**
	 * Get the Data Source Name (DSN) for the MySQL connection.
	 *
	 * @return string The DSN string.
	 */
	public function getDSN(): string{
		if($this->unix_socket !== null){
			return "mysql:unix_socket={$this->unix_socket};dbname={$this->database};charset={$this->charset}";
		}

		return "mysql:host={$this->host};port={$this->port};dbname={$this->database};charset={$this->charset}";
	}
}