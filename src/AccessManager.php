<?php

namespace CVLB\AccessManager;

use CVLB\AccessManager\Exception\AccessManagerException;
use STS\Backoff\Backoff;

abstract class AccessManager
{
    /**
     * @var string 
     */
    private $awsKey;

    /**
     * @var string
     */
    private $awsSecret;

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
     * @param array $config - expecting keys: aws_key, aws_secret, and encryption_key 
     */
    public function __construct(array $config)
    {
        $this->setAwsKey($config['aws_key']);
        $this->setAwsSecret($config['aws_secret']);
        $this->setEncryptionKey($config['encryption_key']);
        
        // Init the backoff object
        $this->setBackoff();
    }

    /**
     * @param string $string
     */
    private function setAwsKey(string $string): void
    {
        $this->awsKey = $string;
    }

    /**
     * @return string
     */
    private function getAwsKey(): string
    {
        return $this->awsKey;
    }

    /**
     * @param string $string
     */
    private function setAwsSecret(string $string): void
    {
        $this->awsSecret = $string;
    }

    private function getAwsSecret(): string
    {
        return $this->awsSecret;
    }

    /**
     * @param string $string
     */
    private function setEncryptionKey(string $string): void
    {
        $this->encryptionKey = $string;
    }

    /**
     * @return string
     */
    private function getEncryptionKey(): string
    {
        return $this->encryptionKey;
    }

    /**
     * Init the Backoff object
     */
    private function setBackoff(): void
    {
        $this->backoff = new Backoff($this->maxRetryAttempts, 'exponential', null, true);
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
        // Look for it in cache first
        $value = $this->fromCache($secretName);

        if (!$value) {
            try {
                // If not found in cache, get from SecretsManager
                $value = $this->backoff->run(function() use($secretName) {
                    return $this->fromSource($secretName);
                });
            } catch (\Exception $e) {
                // Log and notify
                $this->publishToSns();
                throw new AccessManagerException($e->getMessage());
            }
        }
        
        //If no value found, log and notify
        if (!$value) {
            $this->publishToSns();
            throw new AccessManagerException("Unable to find value for [$secretName]");
        }
        
        // Decode the json
        $value = json_decode($value, true);

        if (!isset($value[$key])) {
            // Log and notify
            $this->publishToSns();
            throw new AccessManagerException("Key [$key] not found in the value for [$secretName]");
        }
        
        return $value[$key];
    }

    /**
     * Get vale from cache for the given $key
     * @param string $key
     * @return string|null
     * @throws \Exception
     */
    protected function fromCache(string $key): ?string
    {
        // Fetch from implemented cache service
        $value = $this->fetchFromCache($key);
        
        if (!$value)
            return null;
        
        // decrypt the cached value
        $unencryptedValue = $this->decryptValue($value);
        
        if ($unencryptedValue) {
            // return it
            return $unencryptedValue;
        }
        else {
            // unable to decrypt so get from SecretsManager
            return $this->fromSource($key);
        }
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
     * Get value from SecretsManager service for given $key
     * @param string $key
     * @return string|null
     * @throws \Exception
     */
    protected function fromSource(string $key): ?string
    {
        try {
            $value = $this->fetchFromSource($key);

            if (!$value)
                return null;
        } catch (\Exception $e) {
            throw $e;
        }
        
        // Encrypt value for storage
        $encryptedValue = $this->encryptValue($value);
        
        // Add to cache
        $this->storeToCache($key, $encryptedValue);
        
        return $value;
    }

    /**
     * Get secret from SecretsManager
     * @param string $secretName
     * @return string|null
     * @throws \Exception
     */
    protected function fetchFromSource(string $secretName): ?string
    {
        // ToDo: move to Instance Role
        $credentials = new \Aws\Credentials\Credentials($this->awsKey, $this->awsSecret);
        
        // Init the AWS client
        $client = new \Aws\SecretsManager\SecretsManagerClient([
            'version' => '2017-10-17',
            'region' => 'us-west-2',
            'credentials' => $credentials
        ]);

        try {
            // Make call
            $result = $client->getSecretValue([
                'SecretId' => $secretName,
            ]);

        } catch (\Aws\Exception\AwsException $e) {
            $error = $e->getAwsErrorCode();
            if ($error == 'DecryptionFailureException') {
                // Secrets Manager can't decrypt the protected secret text using the provided AWS KMS key.
                // Handle the exception here, and/or rethrow as needed.
                throw $e;
            }
            if ($error == 'InternalServiceErrorException') {
                // An error occurred on the server side.
                // Handle the exception here, and/or rethrow as needed.
                throw $e;
            }
            if ($error == 'InvalidParameterException') {
                // You provided an invalid value for a parameter.
                // Handle the exception here, and/or rethrow as needed.
                throw $e;
            }
            if ($error == 'InvalidRequestException') {
                // You provided a parameter value that is not valid for the current state of the resource.
                // Handle the exception here, and/or rethrow as needed.
                throw $e;
            }
            if ($error == 'ResourceNotFoundException') {
                // We can't find the resource that you asked for.
                // Handle the exception here, and/or rethrow as needed.
                throw $e;
            }

            throw $e;
            
        } catch (\Exception $e) {
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
    
    private function publishToSns()
    {
        /*
         * ToDo: accept an array of SNS topics => message pairs, and publish message(s) to topic(s)
         */
    }
}