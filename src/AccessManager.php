<?php

namespace CVLB\AccessManager;

use Aws\Exception\AwsException;
use Aws\SecretsManager\SecretsManagerClient;
use CVLB\AccessManager\Exception\AccessManagerException;
use CVLB\AccessManager\Factories\CloudWatchLoggerFactory;
use Exception;
use Monolog\Logger;
use STS\Backoff\Backoff;

abstract class AccessManager
{
    /**
     * @var int
     */
    protected $maxRetryAttempts = 5;

    /**
     * @var string
     */
    private $openSslCipherAlgo = 'AES-256-GCM';

    /**
     * @var string
     */
    private $encryptionKey;

    /**
     * @var bool
     */
    protected $useCache = true;

    /**
     * @var string
     */
    protected $instanceId;

    /**
     * @var Backoff 
     */
    private $backoff;

    /**
     * @var SecretsManagerClient
     */
    private $secretsManager;

    /**
     * @var Logger
     */
    private $logger;

    /**
     * @param string $encryption_key
     * @param array $cloudWatchConfig - [string cloudwatch_group, string application_name, int retention, array tags]
     * @param bool $use_cache
     */
    public function __construct(string $encryption_key, array $cloudWatchConfig, bool $use_cache = true)
    {
        $this->setEncryptionKey($encryption_key);
        $this->setUseCache($use_cache);
        $this->setInstanceid();
        
        // Init STS\Backoff\Backoff
        $this->setBackoff();

        // Init SecretsManagerClient
        $this->setSecretsManager();

        // Init Monolog\Logger with CloudWatch
        $this->setLogger($cloudWatchConfig);
    }

    /**
     * @param string $string
     */
    private function setEncryptionKey(string $string): void
    {
        $this->encryptionKey = $string;
    }

    /**
     * @param bool $bool
     */
    private function setUseCache(bool $bool): void
    {
        $this->useCache = $bool;
    }

    /**
     * @return bool
     */
    public function getUseCache(): bool
    {
        return $this->useCache;
    }

    /**
     * Set the instance id used for logging
     */
    private function setInstanceId(): void
    {
        $this->instanceId = self::findInstanceId();
    }

    /**
     * @return string
     */
    public function getInstanceId(): string
    {
        return $this->instanceId;
    }

    /**
     * Init the Backoff object
     */
    private function setBackoff(): void
    {
        if (!$this->backoff)
            $this->backoff = new Backoff($this->maxRetryAttempts, 'exponential', null, true);
    }

    /**
     * Init SecretsManagerClient
     */
    private function setSecretsManager(): void
    {
        if (!$this->secretsManager)
            $this->secretsManager = new SecretsManagerClient([
                'version' => '2017-10-17',
                'region' => 'us-west-2', // ToDo: make variable
            ]);
    }

    /**
     * Init Monolog\Logger using a CloudWatch handler
     * @param array $cloudWatchConfig - [string cloudwatch_group, string application_name, int retention, array tags]
     * @throws Exception
     */
    private function setLogger(array $cloudWatchConfig): void
    {
        if (!$this->logger) {
            $cloudWatchConfig['sdk'] = [
                'version' => 'latest', // ToDo: lock a version
                'region' => 'us-west-2', // ToDo: will need to be variable
            ];

            $cloudWatchConfig['instance_id'] = $this->getInstanceId();

            $this->logger = CloudWatchLoggerFactory::create($cloudWatchConfig);
        }
    }

    /**
     * Get value for the $key from cache or AWS SecretsManager service
     * @param string $secretName
     * @param string $key
     * @return string|null
     * @throws AccessManagerException
     */
    public function access(string $secretName, string $key): ?string
    {
        // Look for it in cache first and decode
        $value = json_decode($this->fromCache($secretName), true);

        if (!$value || !isset($value[$key])) {
            // If not found in cache, get from SecretsManager
            try {
                // Request within the backoff
                // @see \STS\Backoff\Backoff
                $value = $this->backoff->run(function() use($secretName) {
                    return $this->fromSource($secretName);
                });

                // Decode the json
                $value = json_decode($value, true);

                //If no value found
                if (!$value) {
                    $this->logAccess(Logger::CRITICAL, "Unable to find value for secret", ['secretName' => $secretName]);
                    return null;
                }

                // Key not found
                if (!isset($value[$key])) {
                    $this->logAccess(Logger::CRITICAL, 'Key not found in value', ['secretName' => $secretName, 'key' => $key]);
                    return null;
                }

                // Log access
                $this->logAccess(Logger::INFO, 'Secret Accessed', ['secret' => $secretName, 'key' => $key]);

            } catch (Exception $e) {
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }
        }
        
        return $value[$key];
    }

    /**
     * Get value from cache for the given $secretName
     * @param string $secretName
     * @return string|null
     */
    protected function fromCache(string $secretName): ?string
    {
        // Bypass if not using cache
        if ($this->useCache === false)
            return null;

        // Fetch from implemented cache service
        $value = $this->fetchFromCache($secretName);
        
        if (!$value)
            return null;
        
        // decrypt the cached value
        return $this->decryptValue($value);
    }

    /**
     * Get value from SecretsManager service for given $key
     * @param string $secretName
     * @return string|null
     * @throws Exception
     */
    protected function fromSource(string $secretName): ?string
    {
        $value = $this->fetchFromSource($secretName);

        if (!$value)
            return null;
        
        // Encrypt value for storage
        $encryptedValue = $this->encryptValue($value);
        
        // Add to cache
        $this->storeToCache($secretName, $encryptedValue);
        
        return $value;
    }

    /**
     * Get secret from SecretsManager
     * @param string $secretName
     * @return string|null
     * @throws Exception
     * @see https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.SecretsManager.SecretsManagerClient.html
     */
    protected function fetchFromSource(string $secretName): ?string
    {
        try {
            // Make call
            $result = $this->secretsManager->getSecretValue([
                'SecretId' => $secretName,
            ]);

        } catch (AwsException $e) {
            $error = $e->getAwsErrorCode();
            if ($error == 'DecryptionFailureException') {
                // Secrets Manager can't decrypt the protected secret text using the provided AWS KMS key.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }
            if ($error == 'InternalServiceErrorException') {
                // An error occurred on the server side.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }
            if ($error == 'InvalidParameterException') {
                // You provided an invalid value for a parameter.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }
            if ($error == 'InvalidRequestException') {
                // You provided a parameter value that is not valid for the current state of the resource.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }
            if ($error == 'ResourceNotFoundException') {
                // We can't find the resource that you asked for.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
                return null;
            }

            $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
            return null;
            
        } catch (Exception $e) {
            $this->logAccess(Logger::CRITICAL, $e->getMessage(), $e->getTrace());
            return null;
        }

        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if (isset($result['SecretString'])) {
            $secret = $result['SecretString'];
        } else {
            $secret = base64_decode($result['SecretBinary']);
        }
        
        return $secret;
    }

    /**
     * Encrypt the $value for storage into cache
     * @param string $value - text to encode
     * @return false|string - base64-encoded ciphertext
     */
    private function encryptValue(string $value): ?string
    {
        // determine the length for the initialization vector based on the cipher being used
        $iv_length = openssl_cipher_iv_length($this->openSslCipherAlgo);
        
        // initialization vector
        $iv = substr(md5(microtime()),0, $iv_length);
        
        // Do encryption
        $encrypted = openssl_encrypt($value, $this->openSslCipherAlgo, $this->encryptionKey, 0, $iv,$tag);

        if ($encrypted) {
            // encode the iv, and tag with the encrypted text, they are both required for decryption           
            return base64_encode($iv . $encrypted . $tag);
        }
        else
            return false;
    }

    /**
     * Decrypt $value from cache for use
     * @param string $value - base64-encoded ciphertext iv.encryptedValue.tag
     * @return false|string
     */
    private function decryptValue(string $value): ?string
    {
        // Our encryption process wrapped the ciphertext in base64 encoding, so decode it
        $encrypted = base64_decode($value);

        // determine the length for the initialization vector based on the cipher being used
        $iv_length = openssl_cipher_iv_length($this->openSslCipherAlgo);
        
        // extract the initialization vector
        $iv = substr($encrypted, 0, $iv_length);
        
        // extract the tag (we used the default tag length of 16)
        $authTag = substr($encrypted, -16);

        // extract the value we want to decrypt (between the iv length and the default tag length of 16)
        $encryptedValue = substr($encrypted, $iv_length, -16);
        
        return openssl_decrypt($encryptedValue, $this->openSslCipherAlgo, $this->encryptionKey, 0, $iv, $authTag);
    }

    /**
     * Log event to CloudWatch
     * @param int $level
     * @param string $message
     * @param array $params
     */
    protected function logAccess(int $level, string $message, array $params): void
    {
        $logParams = array_merge($this->logParams(), $params);

        switch ($level)
        {
            case Logger::DEBUG:
                $this->logger->debug($message, $logParams);
                break;
            case Logger::INFO:
                $this->logger->info($message, $logParams);
                break;
            case Logger::NOTICE:
                $this->logger->notice($message, $logParams);
                break;
            case Logger::WARNING:
                $this->logger->warning($message, $logParams);
                break;
            case Logger::CRITICAL:
                $this->logger->critical($message, $logParams);
                break;
            case Logger::ALERT:
                $this->logger->alert($message, $logParams);
                break;
            case Logger::EMERGENCY:
                $this->logger->emergency($message, $logParams);
                break;
            default:
                $this->logger->log(000, $message, $logParams);
        }
    }

    /**
     * Find the instance-id from the AWS resource or use the server IP
     * @return string|null
     */
    static function findInstanceId(): ?string
    {
        if (!$instance_id = @file_get_contents("http://instance-data/latest/meta-data/instance-id"))
            $instance_id = $_SERVER['SERVER_ADDR'] ?? null;

        return $instance_id;
    }

    /**
     * Define extraction from cache service in extending class
     * @param string $key
     * @return string|null
     */
    abstract protected function fetchFromCache(string $key): ?string;

    /**
     * Define storage into cache service in extending class
     * @param string $key
     * @param string $value
     * @return bool|null
     */
    abstract protected function storeToCache(string $key, string $value): ?bool;

    /**
     * Define clearing of key(s) from cache service in extending class
     * @param array $keys
     * @return int|null
     */
    abstract protected function clearFromCache(array $keys): int;

    /**
     * Define method to return additional params to be added to log
     * This allows for additional, customized log info per application
     * e.g. user_id, username, etc
     * @return array
     */
    abstract protected function logParams(): array;
}