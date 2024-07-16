import datetime

from aws_cdk import (
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
    aws_ec2 as _ec2,
    aws_ecs as _ecs,
    aws_iam as _iam,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_secretsmanager as _secretsmanager,
    aws_ssm as _ssm
)

from constructs import Construct

class LunkerzeroInspection(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    ### S3 BUCKET ###

        bucket = _s3.Bucket(
            self, 'bucket',
            bucket_name = 'lunkerinspection',
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            enforce_ssl = True,
            versioned = False
        )

        bucket.add_lifecycle_rule(
            expiration = Duration.days(1),
            noncurrent_version_expiration = Duration.days(1)
        )

        bucketname = _ssm.StringParameter(
            self, 'bucketname',
            description = 'Lunker Zero S3 Bucket',
            parameter_name = '/lunkerzero/bucket',
            string_value = bucket.bucket_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

    ### IAM USER ###

        user = _iam.User(
            self, 'user'
        )

        user.add_to_policy(
            statement = _iam.PolicyStatement(
                effect = _iam.Effect.ALLOW,
                actions = [
                    's3:PutObject'
                ],
                resources = [
                    bucket.arn_for_objects('*')
                ]
            )
        )

        user.add_to_policy(
            statement = _iam.PolicyStatement(
                effect = _iam.Effect.ALLOW,
                actions = [
                    's3:GetBucketLocation'
                ],
                resources = [
                    bucket.bucket_arn
                ]
            )
        )

        accesskey = _iam.AccessKey(
            self, 'accesskey',
            user = user,
            serial = epoch
        )

    ### SECRET MANAGER ###

        secret = _secretsmanager.Secret(
            self, 'secret',
            secret_object_value={
                "accesskey": SecretValue.unsafe_plain_text(accesskey.access_key_id),
                "secretkey": accesskey.secret_access_key
            },
            removal_policy = RemovalPolicy.DESTROY
        )

    ### PARAMETERS ###

        vpcid = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'vpcid',
            parameter_name = '/network/vpc'
        )

        azid = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'azid',
            parameter_name = '/network/az'
        )

        subid = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'subid',
            parameter_name = '/network/subnet'
        )

        rtbid = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'rtbid',
            parameter_name = '/network/rtb'
        )

    ### VPC NETWORK ###

        vpc = _ec2.Vpc.from_vpc_attributes(
            self, 'vpc',
            vpc_id = vpcid.string_value,
            availability_zones = [
                azid.string_value
            ],
            public_subnet_ids = [
                subid.string_value
            ],
            public_subnet_route_table_ids = [
                rtbid.string_value
            ]
        )

    ### FARGATE ECS ###

        cluster = _ecs.Cluster(
            self, 'cluster',
            vpc = vpc
        )

    ### FARGATE LOGS ###

        logs = _logs.LogGroup(
            self, 'logs',
            log_group_name = '/aws/fargate',
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        logging = _ecs.AwsLogDriver(
            stream_prefix = 'inspection',
            log_group = logs
        )

    ### FARGATE TASK ###

        task = _ecs.TaskDefinition(
            self, 'task',
            cpu = '2048',
            memory_mib = '4096',
            compatibility = _ecs.Compatibility.FARGATE
        )

        task_policy = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions = [
                'ecr:GetAuthorizationToken',
                'ecr:BatchCheckLayerAvailability',
                'ecr:GetDownloadUrlForLayer',
                'ecr:BatchGetImage',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources = [
                '*'
            ]
        )

        task.add_to_task_role_policy(task_policy)

    ### FARGATE CONTAINER ###

        container = task.add_container(
            'container',
            image = _ecs.ContainerImage.from_asset('lunker/inspection'),
            logging = logging,
            environment = {
                'INSPECT_URL': 'https://www.eicar.org/download-anti-malware-testfile/',
                'STORE_ENDPOINT_URL': bucket.url_for_object(),
                'STORE_PATH': '/eicar.org/',
                'STORE_FILENAME': 'eicar.org.wacz'
            },
            secrets = {
                'STORE_ACCESS_KEY': _ecs.Secret.from_secrets_manager(secret, 'accesskey'),
                'STORE_SECRET_KEY': _ecs.Secret.from_secrets_manager(secret, 'secretkey')
            }
        )

    ### PARAMETERS ###

        clustername = _ssm.StringParameter(
            self, 'clustername',
            description = 'Lunker Zero Fargate Cluster',
            parameter_name = '/fargate/cluster',
            string_value = cluster.cluster_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

        taskdef = _ssm.StringParameter(
            self, 'taskdef',
            description = 'Lunker Zero Fargate Task',
            parameter_name = '/fargate/task',
            string_value = task.task_definition_arn,
            tier = _ssm.ParameterTier.STANDARD,
        )

        dockername = _ssm.StringParameter(
            self, 'dockername',
            description = 'Lunker Zero Fargate Docker',
            parameter_name = '/fargate/docker',
            string_value = container.container_name,
            tier = _ssm.ParameterTier.STANDARD,
        )