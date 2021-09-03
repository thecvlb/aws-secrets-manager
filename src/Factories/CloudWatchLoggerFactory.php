<?php

namespace CVLB\AccessManager\Factories;

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Maxbanton\Cwh\Handler\CloudWatch;
use Monolog\Logger;

class CloudWatchLoggerFactory
{
    /**
     * Create a custom Monolog instance.
     * @param array $config
     * @return Logger
     * @throws \Exception
     * @see https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CloudWatchLogs.CloudWatchLogsClient.html
     */
    public static function create(array $config): Logger
    {
        // Connection array
        $sdkParams = $config['sdk'];

        // AWS tags
        $tags = $config['tags'] ?? [ ];

        // Create a name with an instance id and application name
        // e.g. i-0a9649ddc6f8093aa:AdminPortal:AccessManager
        $instance_id = $config['instance_id'] ? $config['instance_id'].':' : null;
        $name = $instance_id.$config['application_name'].':AccessManager';

        // Log group name, will be created if none
        $groupName = $config['cloudwatch_group'];

        // Log stream name, will be created if none
        $streamName = 'AccessManager';

        // Days to keep logs, 14 by default. Set to `null` to allow indefinite retention.
        $retentionDays = $config['retention'];

        // Instantiate AWS SDK CloudWatch Logs Client
        $client = new CloudWatchLogsClient($sdkParams);

        // Instantiate handler (tags are optional)
        $handler = new CloudWatch($client, $groupName, $streamName, $retentionDays, 10000, $tags);

        // Create a log channel
        $logger = new Logger($name);

        // Set handler
        $logger->pushHandler($handler);

        return $logger;
    }
}