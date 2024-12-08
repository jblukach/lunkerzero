from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_ssm as _ssm
)

from constructs import Construct

class LunkerzeroProduction(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

    ### LAYERS ###

        extensions = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'extensions',
            parameter_name = '/extensions/account'
        )

        censys = _lambda.LayerVersion.from_layer_version_arn(
            self, 'censys',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:censys:13'
        )

        getpublicip = _lambda.LayerVersion.from_layer_version_arn(
            self, 'getpublicip',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:getpublicip:14'
        )

        netaddr = _lambda.LayerVersion.from_layer_version_arn(
            self, 'netaddr',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:netaddr:8'
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:requests:7'
        )

    ### IAM ###

        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'dynamodb:DeleteItem',
                    'dynamodb:PutItem',
                    'dynamodb:Query',
                    'ecs:RunTask',
                    'iam:PassRole',
                    's3:GetObject',
                    'ssm:GetParameter'
                ],
                resources = [
                    '*'
                ]
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'securityhub:BatchImportFindings'
                ],
                resources = [
                    'arn:aws:securityhub:'+region+':'+account+':product/'+account+'/default'
                ]
            )
        )

    ### PARAMETERS ###

        cluster = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'cluster',
            parameter_name = '/fargate/cluster'
        )

        container = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'container',
            parameter_name = '/fargate/inspection/container'
        )

        security = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'security',
            parameter_name = '/network/sg'
        )

        subnet = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'subnet',
            parameter_name = '/network/subnet'
        )

        taskdef = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'taskdef',
            parameter_name = '/fargate/inspection/task'
        )

        tld = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'tld',
            parameter_name = '/lunkerzero/tldtable'
        )

     ### LUNKER ###

        fishes = []
        fishes.append('northern')
        fishes.append('pike')

        for fish in fishes:

            table = _dynamodb.Table(
                self, 'table'+fish,
                table_name = fish,
                partition_key = {
                    'name': 'pk',
                    'type': _dynamodb.AttributeType.STRING
                },
                sort_key = {
                    'name': 'sk',
                    'type': _dynamodb.AttributeType.STRING
                },
                billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
                removal_policy = RemovalPolicy.DESTROY,
                point_in_time_recovery = True,
                deletion_protection = True
            )

            lunker = _lambda.Function(
                self, 'lunker'+fish,
                function_name = fish,
                runtime = _lambda.Runtime.PYTHON_3_13,
                architecture = _lambda.Architecture.ARM_64,
                code = _lambda.Code.from_asset('lunker/production'),
                timeout = Duration.seconds(900),
                handler = 'lunker.handler',
                environment = dict(
                    AWS_ACCOUNT = account,
                    CLUSTER_NAME = cluster.string_value,
                    CONTAINER_NAME = container.string_value,
                    DYNAMODB_TABLE = table.table_name,
                    DYNAMODB_TLDTABLE = tld.string_value,
                    LUNKER_FISH = fish,
                    LUNKER_LIMIT = '250',
                    SECURITY_GROUP = security.string_value,
                    SUBNET_ID = subnet.string_value,
                    TASK_DEFINITION = taskdef.string_value
                ),
                memory_size = 512,
                retry_attempts = 0,
                role = role,
                layers = [
                    getpublicip,
                    requests
                ]
            )

            logs = _logs.LogGroup(
                self, 'logs'+fish,
                log_group_name = '/aws/lambda/'+lunker.function_name,
                retention = _logs.RetentionDays.ONE_DAY,
                removal_policy = RemovalPolicy.DESTROY
            )

            angler = _lambda.Function(
                self, 'angler'+fish,
                function_name = fish+'hook',
                runtime = _lambda.Runtime.PYTHON_3_12,
                architecture = _lambda.Architecture.ARM_64,
                code = _lambda.Code.from_asset('lunker/development'),
                timeout = Duration.seconds(900),
                handler = 'angler.handler',
                environment = dict(
                    AWS_ACCOUNT = account,
                    CENSYS_API_ID = '-',
                    CENSYS_API_SECRET = '-',
                    DYNAMODB_TABLE = table.table_name,
                    LUNKER_FISH = fish,
                    REGION = region,
                    S3_BUCKET = 'cloudcruftbucket'
                ),
                memory_size = 512,
                retry_attempts = 0,
                role = role,
                layers = [
                    censys,
                    getpublicip,
                    netaddr
                ]
            )

            cwl = _logs.LogGroup(
                self, 'cwl'+fish,
                log_group_name = '/aws/lambda/'+angler.function_name,
                retention = _logs.RetentionDays.ONE_DAY,
                removal_policy = RemovalPolicy.DESTROY
            )

            event = _events.Rule(
                self, 'event'+fish,
                schedule = _events.Schedule.cron(
                    minute = '7',
                    hour = '*',
                    month = '*',
                    week_day = '*',
                    year = '*'
                )
            )

            event.add_target(
                _targets.LambdaFunction(
                    angler,
                    event = _events.RuleTargetInput.from_object(
                        {
                            "censys": "search"
                        }
                    )
                )
            )

            event.add_target(
                _targets.LambdaFunction(
                    angler,
                    event = _events.RuleTargetInput.from_object(
                        {
                            "osint": "dns"
                        }
                    )
                )
            )

            event.add_target(
                _targets.LambdaFunction(
                    angler,
                    event = _events.RuleTargetInput.from_object(
                        {
                            "osint": "ipv4"
                        }
                    )
                )
            )

            event.add_target(
                _targets.LambdaFunction(
                    angler,
                    event = _events.RuleTargetInput.from_object(
                        {
                            "osint": "ipv6"
                        }
                    )
                )
            )
