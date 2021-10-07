# AWS Secrets Manager

Add AWS managed secrets to your project.

Retrieved secrets are stored in a local cache service that must be defined by an extending class. The secrets are encrypted with the `AES-256-GCM` cipher and a provided encryption key before being sent to the cache service, and decrypted when accessed.

AWS Credentials should be provided via the default Credential Provider and should allow reading from SecretsManager and writing to CloudWatchLogs. 

## Installation

Installation via [Composer](https://getcomposer.org/). First, add the repository to your `composer.json` file:

```bash
"repositories":[
        {
            "type": "vcs",
            "url": "git@github.com:thecvlb/aws-secrets-manager.git"
        }
    ]
```

And add the package to your `requirements`:
```bash
"thecvlb/aws-secrets-manager": "1.*"
```

## Usage

You must extend the abstract `AccessManager` class to define the caching methods used by your application. Then, using the extending class, invoke the `access()` method to retrieve a secret:

```php
$redisAccessManager = new \RedisAccessManager(
    $_ENV['ENCRYPTION_KEY'], 
    [
        'application_name' => $_ENV['APP_NAME'],
        'cloudwatch_group' => 'aws-cloudtrail-logs-202108171424',
        'retention' => 14,
        'tags' => []
    ], 
    $_ENV['USE_SECRETS_CACHE']
);
```

The `access()` method requires an `AWS SecretName`, returning the json string:
```php
echo $redisAccessManager->access($_ENV['DB_SECRET_NAME']);
'{"user":"myuser","password":"12345"}'
```

Or pass the `key` to return a specific value string from the secret:
```php
echo $redisAccessManager->access($_ENV['DB_SECRET_NAME'], 'password');
'12345'
```

You can create a facade for your extended class to invoke the method as a static function:
```php
$db_password = RedisAccessFacade::access($_ENV['DB_SECRET_NAME'], 'password')
```