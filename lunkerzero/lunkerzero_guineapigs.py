from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_cloudwatch as _cloudwatch,
    aws_cloudwatch_actions as _actions,
    aws_dynamodb as _dynamodb,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_sns as _sns,
    aws_ssm as _ssm
)

from constructs import Construct

class LunkerzeroGuineapigs(Stack):

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
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:censys:7'
        )

        getpublicip = _lambda.LayerVersion.from_layer_version_arn(
            self, 'getpublicip',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:getpublicip:12'
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = 'arn:aws:lambda:'+region+':'+extensions.string_value+':layer:requests:5'
        )

    ### TOPIC ###

        topic = _sns.Topic.from_topic_arn(
            self, 'topic',
            topic_arn = 'arn:aws:sns:'+region+':'+account+':lunkerzero'
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

    ### PARAMETERS ###

        tld = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'tld',
            parameter_name = '/lunkerzero/tldtable'
        )

     ### LUNKER ###

        fishes = []
        fishes.append('perch')

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
                runtime = _lambda.Runtime.PYTHON_3_12,
                architecture = _lambda.Architecture.ARM_64,
                code = _lambda.Code.from_asset('lunker/guineapigs'),
                timeout = Duration.seconds(900),
                handler = 'lunker.handler',
                environment = dict(
                    AWS_ACCOUNT = account,
                    CENSYS_API_ID = '-',
                    CENSYS_API_SECRET = '-',
                    DYNAMODB_TABLE = table.table_name,
                    DYNAMODB_TLDTABLE = tld.string_value,
                    LUNKER_FISH = fish,
                    LUNKER_LIMIT = '10'
                ),
                memory_size = 512,
                retry_attempts = 0,
                role = role,
                layers = [
                    censys,
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

            alarm = _cloudwatch.Alarm(
                self, 'alarm'+fish,
                comparison_operator = _cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                threshold = 0,
                evaluation_periods = 1,
                metric = lunker.metric_errors(
                    period = Duration.minutes(1)
                )
            )

            alarm.add_alarm_action(
                _actions.SnsAction(topic)
            )
