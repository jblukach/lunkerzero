from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_cloudwatch as _cloudwatch,
    aws_cloudwatch_actions as _actions,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_sns as _sns,
    aws_ssm as _ssm
)

from constructs import Construct

class LunkerzeroVerification(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

    ### LAMBDA LAYERS ###

        extensions = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'extensions',
            parameter_name = '/extensions/account'
        )

        getpublicip = _lambda.LayerVersion.from_layer_version_arn(
            self, 'getpublicip',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:getpublicip:14'
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:requests:7'
        )

    ### DATABASE ###

        table = _dynamodb.Table(
            self, 'table',
            table_name = 'tld',
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

    ### PARAMETER ###

        parameter = _ssm.StringParameter(
            self, 'parameter',
            description = 'Top Level Domain (TLD) Table',
            parameter_name = '/lunkerzero/tldtable',
            string_value = table.table_name,
            tier = _ssm.ParameterTier.STANDARD,
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
                    'dynamodb:Query'
                ],
                resources = [
                    '*'
                ]
            )
        )

    ### TLD ###

        tld = _lambda.Function(
            self, 'tld',
            function_name = 'tld',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('lunker/verification'),
            timeout = Duration.seconds(900),
            handler = 'tld.handler',
            environment = dict(
                AWS_ACCOUNT = account,
                TLD_TABLE = table.table_name
            ),
            memory_size = 256,
            retry_attempts = 0,
            role = role,
            layers = [
                getpublicip,
                requests
            ]
        )

        logs = _logs.LogGroup(
            self, 'logs',
            log_group_name = '/aws/lambda/'+tld.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        event = _events.Rule(
            self, 'event',
            schedule = _events.Schedule.cron(
                minute = '0',
                hour = '12',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        event.add_target(
            _targets.LambdaFunction(tld)
        )
