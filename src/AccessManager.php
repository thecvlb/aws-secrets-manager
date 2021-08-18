<?php

namespace CVLB\AccessManager;

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;
use Aws\SecretsManager\SecretsManagerClient;
use CVLB\AccessManager\Exception\AccessManagerException;
use CVLB\AccessManager\Factories\CloudWatchLoggerFactory;
use Exception;
use Maxbanton\Cwh\Handler\CloudWatch;
use Monolog\Logger;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogHandler;
use STS\Backoff\Backoff;

abstract class AccessManager
{
    /**
     * @var Credentials
     */
    private $credentials;

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
     * @var Backoff 
     */
    private $backoff;

    /**
     * @var bool
     */
    protected $useCache = true;

    private $logger;

    /**
     * @param array $config - expecting keys: aws_key, aws_secret, encryption_key, and optionally, use_cache
     */
    public function __construct(array $config)
    {
        $this->setCredentials($config['aws_key'], $config['aws_secret']);
        $this->setEncryptionKey($config['encryption_key']);
        $this->setUseCache($config['use_cache'] ?? true); // default to true
        
        // Init the backoff object
        $this->setBackoff();

        // Init the logger
        $this->setLogger();
    }

    private function setCredentials(string $awsKey, string $awsSecret): void
    {
        // ToDo: move to Instance Role
        $this->credentials = new Credentials($awsKey, $awsSecret);
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
     * Init the Backoff object
     */
    private function setBackoff(): void
    {
        $this->backoff = new Backoff($this->maxRetryAttempts, 'exponential', null, true);
    }

    private function setLogger(): void
    {
        $cloudwatchConfig = [
            'sdk' => [
                'version' => 'latest',
                'region' => 'us-west-2',
                'credentials' => $this->credentials
            ],
            'name' => 'AccessManagerLogger',
            'cloudwatch_group' => 'aws-cloudtrail-logs-202108171424',
            'retention' => 14
        ];
        $logger = new CloudWatchLoggerFactory();
        $this->logger = $logger($cloudwatchConfig);
    }

    /**
     * Get value for the $key from cache or AWS SecretsManager service
     * @param string $secretName
     * @param string $key
     * @return string
     * @throws AccessManagerException
     */
    public function access(string $secretName, string $key): string
    {
        // Look for it in cache first and decode
        $value = json_decode($this->fromCache($secretName), true);

        if (!$value || !isset($value[$key])) {
            try {
                // If not found in cache, get from SecretsManager
                $value = $this->backoff->run(function() use($secretName) {
                    return $this->fromSource($secretName);
                });

                // Decode the json
                $value = json_decode($value, true);

                //If no value found
                if (!$value) {
                    $this->logAccess(['message' => __FILE__. ':'.__LINE__."|Unable to find value for [$secretName]"]);
                    $this->notify(__FILE__. ':'.__LINE__."|Unable to find value for [$secretName]");
                    throw new AccessManagerException(__FILE__. ':'.__LINE__."|Unable to find value for [$secretName]");
                }

                // Key not found
                if (!isset($value[$key])) {
                    $this->logAccess(['message' => __FILE__. ':'.__LINE__."|Key [$key] not found in the value for [$secretName]"]);
                    $this->notify(__FILE__. ':'.__LINE__."|Key [$key] not found in the value for [$secretName]");
                    throw new AccessManagerException(__FILE__. ':'.__LINE__."|Key [$key] not found in the value for [$secretName]");
                }

            } catch (Exception $e) {
                $this->logAccess($e->getTraceAsString());
                $this->notify($e->getTraceAsString());
                throw new AccessManagerException($e->getMessage());
            }
        }

        // Log access
        $this->logAccess(['secret' => $secretName, 'key' => $key]);
        
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
     */
    protected function fetchFromSource(string $secretName): ?string
    {
        // Init the AWS client
        $client = new SecretsManagerClient([
            'version' => '2017-10-17',
            'region' => 'us-west-2',
            'credentials' => $this->credentials
        ]);

        try {
            // Make call
            $result = $client->getSecretValue([
                'SecretId' => $secretName,
            ]);

        } catch (AwsException $e) {
            $error = $e->getAwsErrorCode();
            if ($error == 'DecryptionFailureException') {
                // Secrets Manager can't decrypt the protected secret text using the provided AWS KMS key.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(['message' => $e->getTraceAsString()]);
                $this->notify($e->getTraceAsString());
                throw $e;
            }
            if ($error == 'InternalServiceErrorException') {
                // An error occurred on the server side.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(['message' => $e->getTraceAsString()]);
                $this->notify($e->getTraceAsString());
                throw $e;
            }
            if ($error == 'InvalidParameterException') {
                // You provided an invalid value for a parameter.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(['message' => $e->getTraceAsString()]);
                $this->notify($e->getTraceAsString());
                throw $e;
            }
            if ($error == 'InvalidRequestException') {
                // You provided a parameter value that is not valid for the current state of the resource.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(['message' => $e->getTraceAsString()]);
                $this->notify($e->getTraceAsString());
                throw $e;
            }
            if ($error == 'ResourceNotFoundException') {
                // We can't find the resource that you asked for.
                // Handle the exception here, and/or rethrow as needed.
                $this->logAccess(['message' => $e->getTraceAsString()]);
                $this->notify($e->getTraceAsString());
                throw $e;
            }

            $this->logAccess(['message' => $e->getTraceAsString()]);
            $this->notify($e->getTraceAsString());
            throw $e;
            
        } catch (Exception $e) {
            $this->logAccess(['message' => $e->getTraceAsString()]);
            $this->notify($e->getTraceAsString());
            throw $e;
        }

        // Decrypts secret using the associated KMS CMK.
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

    protected function logAccess(array $params)
    {
        $logParams = array_merge($params, $this->logParams());

        $this->logger->notice('AccessManager Event: ', $logParams);
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
     * e.g. user_id, username, etc
     * @return array
     */
    abstract protected function logParams(): array;

    /**
     * Define notification service to be used
     * @param string $message
     * @return bool
     */
    abstract function notify(string $message): bool;
}