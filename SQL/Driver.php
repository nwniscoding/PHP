<?php
namespace SQL;

use PDO;

/**
 * Abstract base class for database drivers.
 */
abstract class Driver{
	/**
	 * The PDO connection instance.
	 * @var PDO|null
	 */
	protected ?PDO $connection = null;

	/**
	 * The database configuration instance.
	 * @var ConfigInterface
	 */
	protected ConfigInterface $config;

	/**
	 * Constructor to initialize the driver with a configuration.
	 *
	 * @param ConfigInterface $config The database configuration.
	 */
	public function __construct(ConfigInterface $config){
		$this->config = $config;
	}

	/**
	 * Connect to the database using the provided configuration.
	 *
	 * @return bool True on successful connection, false otherwise.
	 * 
	 */
	public function connect(): void{
		$this->config->apply(fn(array $configs) => $this->loadConfig($configs));
	}

	/**
	 * Load the database configuration and establish a connection.
	 *
	 * @param array<string, mixed> $configs The configuration parameters.
	 */
	abstract protected function loadConfig(array $configs): void;
}