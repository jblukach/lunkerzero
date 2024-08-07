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

        account = Stack.of(self).account
        region = Stack.of(self).region

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

        #bucket.add_lifecycle_rule(
        #    expiration = Duration.days(1),
        #    noncurrent_version_expiration = Duration.days(1)
        #)

        bucketname = _ssm.StringParameter(
            self, 'bucketname',
            description = 'Lunker Zero Inspection',
            parameter_name = '/lunkerzero/inspection',
            string_value = bucket.bucket_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

        download = _s3.Bucket(
            self, 'download',
            bucket_name = 'lunkerdownload',
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            enforce_ssl = True,
            versioned = False
        )

        #download.add_lifecycle_rule(
        #    expiration = Duration.days(1),
        #    noncurrent_version_expiration = Duration.days(1)
        #)

        downloadname = _ssm.StringParameter(
            self, 'downloadname',
            description = 'Lunker Zero Download',
            parameter_name = '/lunkerzero/download',
            string_value = download.bucket_name,
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
                    download.arn_for_objects('*')
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
                    download.bucket_arn
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

        inspectionlogs = _ecs.AwsLogDriver(
            stream_prefix = 'inspection',
            log_group = logs
        )

        expansionlogs = _ecs.AwsLogDriver(
            stream_prefix = 'expansion',
            log_group = logs
        )

    ### FARGATE TASK ###

        inspectiontask = _ecs.TaskDefinition(
            self, 'inspectiontask',
            cpu = '2048',
            memory_mib = '4096',
            compatibility = _ecs.Compatibility.FARGATE
        )

        expansiontask = _ecs.TaskDefinition(
            self, 'expansiontask',
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

        inspectiontask.add_to_task_role_policy(task_policy)
        expansiontask.add_to_task_role_policy(task_policy)

        task_policy = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions = [
                's3:GetObject',
                's3:PutObject'
            ],
            resources = [
                bucket.arn_for_objects('*'),
                download.arn_for_objects('*')
            ]
        )

        inspectiontask.add_to_task_role_policy(task_policy)
        expansiontask.add_to_task_role_policy(task_policy)

    ### FARGATE CONTAINER ###

        inspectioncontainer = inspectiontask.add_container(
            'inspectioncontainer',
            image = _ecs.ContainerImage.from_asset('lunker/inspection'),
            logging = inspectionlogs,
            environment = {
                'INSPECT_URL': 'https://eicar.org',
                'STORE_ENDPOINT_URL': download.url_for_object(),
                'STORE_REGION': region,
                'STORE_PATH': '/eicar.org/',
                'STORE_FILENAME': 'eicar.org.wacz',
                'CRAWL_ID': 'eicar.org'
            },
            secrets = {
                'STORE_ACCESS_KEY': _ecs.Secret.from_secrets_manager(secret, 'accesskey'),
                'STORE_SECRET_KEY': _ecs.Secret.from_secrets_manager(secret, 'secretkey')
            }
        )

        expansioncontainer = expansiontask.add_container(
            'expansioncontainer',
            image = _ecs.ContainerImage.from_asset('lunker/expansion'),
            logging = expansionlogs,
            environment = {
                'CRAWL_ID': 'eicar.org',
                'S3_DOWNLOAD': download.bucket_name,
                'S3_INSPECT': bucket.bucket_name
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

        inspectiontaskdef = _ssm.StringParameter(
            self, 'inspectiontaskdef',
            description = 'Lunker Zero Inspection Task',
            parameter_name = '/fargate/inspection/task',
            string_value = inspectiontask.task_definition_arn,
            tier = _ssm.ParameterTier.STANDARD,
        )

        expansiontaskdef = _ssm.StringParameter(
            self, 'expansiontaskdef',
            description = 'Lunker Zero Expansion Task',
            parameter_name = '/fargate/expansion/task',
            string_value = expansiontask.task_definition_arn,
            tier = _ssm.ParameterTier.STANDARD,
        )

        inspectcontainer = _ssm.StringParameter(
            self, 'inspectcontainer',
            description = 'Lunker Zero Inspection Container',
            parameter_name = '/fargate/inspection/container',
            string_value = inspectioncontainer.container_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

        expandcontainer = _ssm.StringParameter(
            self, 'expandcontainer',
            description = 'Lunker Zero Expansion Container',
            parameter_name = '/fargate/expansion/container',
            string_value = expansioncontainer.container_name,
            tier = _ssm.ParameterTier.STANDARD,
        )
