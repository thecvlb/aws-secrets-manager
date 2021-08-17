# AWS Secrets Manager

Add AWS managed secrets to your project.

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

And add the package to your `requirements`
```bash
"thecvlb/aws-secrets-manager": "1.*"
```

## Usage

You must extend the abstract `AccessManager` class to define the caching methods used by your application. Then, using the extending class, invoke the `access()` method to retrieve a secret:

```bash
$redisAccessManager = new \RedisAccessManager(
    [
        'aws_key' => $_ENV['AWS_KEY'],
        'aws_secret' => $_ENV['AWS_SECRET'],
        'encryption_key' => $_ENV['ENCRYPTION_KEY'],
    ]
);
```
The `access()` method requires an `AWS SecretName` and the `key`:
```bash
$db_password = $redisAccessManager->access($_ENV['DB_SECRET_NAME'], 'password');
```

You can create a facade for your extended class to invoke the method as a static function:
```bash
$db_password = RedisAccessFacade::access($_ENV['DB_SECRET_NAME'], 'password')
```