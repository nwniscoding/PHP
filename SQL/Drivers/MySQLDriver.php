<?php
namespace SQL\Drivers;

use PDO;
use PDOException;
use SQL\Driver;

/**
 * MySQL database driver implementation.
 */
final class MySQLDriver extends Driver{
	/**
	 * Load the configuration and establish a PDO connection.
	 *
	 * @param array<string, mixed> $configs The configuration parameters.
	 * @return bool True on successful connection, false otherwise.
	 */
	protected function loadConfig(array $configs): bool{
		try{
			$dsn = $this->config->getDSN();
			$this->connection = new PDO($dsn, $configs["username"], $configs["password"]);

			return true;
		}
		catch(PDOException $e){
			return false;
		}
	}
}