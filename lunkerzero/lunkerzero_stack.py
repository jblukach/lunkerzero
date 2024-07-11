import cdk_nag

from aws_cdk import (
    Aspects,
    RemovalPolicy,
    Stack,
    aws_chatbot as _chatbot,
    aws_iam as _iam,
    aws_sns as _sns,
    aws_ssm as _ssm
)

from constructs import Construct

class LunkerzeroStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

    ### CDK NAG ###

        Aspects.of(self).add(
            cdk_nag.AwsSolutionsChecks()
        )

        Aspects.of(self).add(
            cdk_nag.HIPAASecurityChecks()    
        )

        Aspects.of(self).add(
            cdk_nag.NIST80053R5Checks()
        )

        Aspects.of(self).add(
            cdk_nag.PCIDSS321Checks()
        )

        cdk_nag.NagSuppressions.add_stack_suppressions(
            self, suppressions = [
                {"id":"HIPAA.Security-IAMNoInlinePolicy","reason":"The IAM Group, User, or Role contains an inline policy - (Control IDs: 164.308(a)(3)(i), 164.308(a)(3)(ii)(A), 164.308(a)(3)(ii)(B), 164.308(a)(4)(i), 164.308(a)(4)(ii)(A), 164.308(a)(4)(ii)(B), 164.308(a)(4)(ii)(C), 164.312(a)(1))."},
                {"id":"HIPAA.Security-IAMPolicyNoStatementsWithAdminAccess","reason":"The IAM policy grants admin access, meaning the policy allows a principal to perform all actions on all resources - (Control IDs: 164.308(a)(3)(i), 164.308(a)(3)(ii)(A), 164.308(a)(3)(ii)(B), 164.308(a)(4)(i), 164.308(a)(4)(ii)(A), 164.308(a)(4)(ii)(B), 164.308(a)(4)(ii)(C), 164.312(a)(1))."},
                {"id":"HIPAA.Security-IAMPolicyNoStatementsWithFullAccess","reason":"The IAM policy grants full access, meaning the policy allows a principal to perform all actions on individual resources - (Control IDs: 164.308(a)(3)(i), 164.308(a)(3)(ii)(A), 164.308(a)(3)(ii)(B), 164.308(a)(4)(i), 164.308(a)(4)(ii)(A), 164.308(a)(4)(ii)(B), 164.308(a)(4)(ii)(C), 164.312(a)(1))."},
                {"id":"HIPAA.Security-IAMUserNoPolicies","reason":"The IAM policy is attached at the user level - (Control IDs: 164.308(a)(3)(i), 164.308(a)(3)(ii)(A), 164.308(a)(3)(ii)(B), 164.308(a)(4)(i), 164.308(a)(4)(ii)(A), 164.308(a)(4)(ii)(B), 164.308(a)(4)(ii)(C), 164.312(a)(1))."},
                {"id":"HIPAA.Security-SNSEncryptedKMS","reason":"The SNS topic does not have KMS encryption enabled - (Control IDs: 164.312(a)(2)(iv), 164.312(e)(2)(ii))."},
                {"id":"PCI.DSS.321-IAMNoInlinePolicy","reason":"The IAM Group, User, or Role contains an inline policy - (Control IDs: 2.2, 7.1.2, 7.1.3, 7.2.1, 7.2.2)."},
                {"id":"PCI.DSS.321-IAMPolicyNoStatementsWithAdminAccess","reason":"The IAM policy grants admin access, meaning the policy allows a principal to perform all actions on all resources - (Control IDs: 2.2, 7.1.2, 7.1.3, 7.2.1, 7.2.2)."},
                {"id":"PCI.DSS.321-IAMPolicyNoStatementsWithFullAccess","reason":"The IAM policy grants full access, meaning the policy allows a principal to perform all actions on individual resources - (Control IDs: 7.1.2, 7.1.3, 7.2.1, 7.2.2)."},
                {"id":"PCI.DSS.321-IAMUserNoPolicies","reason":"The IAM policy is attached at the user level - (Control IDs: 2.2, 7.1.2, 7.1.3, 7.2.1, 7.2.2)."},
                {"id":"PCI.DSS.321-SNSEncryptedKMS","reason":"The SNS topic does not have KMS encryption enabled - (Control ID: 8.2.1)."},
                {"id":"NIST.800.53.R5-IAMNoInlinePolicy","reason":"The IAM Group, User, or Role contains an inline policy - (Control IDs: AC-2i.2, AC-2(1), AC-2(6), AC-3, AC-3(3)(a), AC-3(3)(b)(1), AC-3(3)(b)(2), AC-3(3)(b)(3), AC-3(3)(b)(4), AC-3(3)(b)(5), AC-3(3)(c), AC-3(3), AC-3(4)(a), AC-3(4)(b), AC-3(4)(c), AC-3(4)(d), AC-3(4)(e), AC-3(4), AC-3(7), AC-3(8), AC-3(12)(a), AC-3(13), AC-3(15)(a), AC-3(15)(b), AC-4(28), AC-6, AC-6(3), AC-24, CM-5(1)(a), CM-6a, CM-9b, MP-2, SC-23(3))."},
                {"id":"NIST.800.53.R5-IAMPolicyNoStatementsWithAdminAccess","reason":"The IAM policy grants admin access, meaning the policy allows a principal to perform all actions on all resources - (Control IDs: AC-2i.2, AC-2(1), AC-2(6), AC-3, AC-3(3)(a), AC-3(3)(b)(1), AC-3(3)(b)(2), AC-3(3)(b)(3), AC-3(3)(b)(4), AC-3(3)(b)(5), AC-3(3)(c), AC-3(3), AC-3(4)(a), AC-3(4)(b), AC-3(4)(c), AC-3(4)(d), AC-3(4)(e), AC-3(4), AC-3(7), AC-3(8), AC-3(12)(a), AC-3(13), AC-3(15)(a), AC-3(15)(b), AC-4(28), AC-5b, AC-6, AC-6(2), AC-6(3), AC-6(10), AC-24, CM-5(1)(a), CM-6a, CM-9b, MP-2, SC-23(3), SC-25)."},
                {"id":"NIST.800.53.R5-IAMPolicyNoStatementsWithFullAccess","reason":"The IAM policy grants full access, meaning the policy allows a principal to perform all actions on individual resources - (Control IDs: AC-3, AC-5b, AC-6(2), AC-6(10), CM-5(1)(a))."},
                {"id":"NIST.800.53.R5-IAMUserNoPolicies","reason":"The IAM policy is attached at the user level - (Control IDs: AC-2i.2, AC-2(1), AC-2(6), AC-3, AC-3(3)(a), AC-3(3)(b)(1), AC-3(3)(b)(2), AC-3(3)(b)(3), AC-3(3)(b)(4), AC-3(3)(b)(5), AC-3(3)(c), AC-3(3), AC-3(4)(a), AC-3(4)(b), AC-3(4)(c), AC-3(4)(d), AC-3(4)(e), AC-3(4), AC-3(7), AC-3(8), AC-3(12)(a), AC-3(13), AC-3(15)(a), AC-3(15)(b), AC-4(28), AC-6, AC-6(3), AC-24, CM-5(1)(a), CM-6a, CM-9b, MP-2, SC-23(3), SC-25)."},
                {"id":"NIST.800.53.R5-SNSEncryptedKMS","reason":"The SNS topic does not have KMS encryption enabled - (Control IDs: AU-9(3), CP-9d, SC-8(3), SC-8(4), SC-13a, SC-28(1))."},
                {"id":"AwsSolutions-IAM4","reason":"The IAM user, role, or group uses AWS managed policies."},
                {"id":"AwsSolutions-IAM5","reason":"The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission."},
                {"id":"AwsSolutions-SNS2","reason":"The SNS Topic does not have server-side encryption enabled."},
                {"id":"AwsSolutions-SNS3","reason":"The SNS Topic does not require publishers to use SSL."},
            ]
        )

    ### PERMISSIONS ###

        cwlperm = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions=[
                'application-autoscaling:DescribeScalingPolicies',
                'application-signals:BatchGet*',
                'application-signals:Get*',
                'application-signals:List*',
                'autoscaling:Describe*',
                'cloudwatch:BatchGet*',
                'cloudwatch:Describe*',
                'cloudwatch:GenerateQuery',
                'cloudwatch:Get*',
                'cloudwatch:List*',
                'logs:Get*',
                'logs:List*',
                'logs:StartQuery',
                'logs:StopQuery',
                'logs:Describe*',
                'logs:TestMetricFilter',
                'logs:FilterLogEvents',
                'logs:StartLiveTail',
                'logs:StopLiveTail',
                'oam:ListSinks',
                'sns:Get*',
                'sns:List*',
                'rum:BatchGet*',
                'rum:Get*',
                'rum:List*',
                'synthetics:Describe*',
                'synthetics:Get*',
                'synthetics:List*',
                'xray:BatchGet*',
                'xray:Get*'
            ],
            resources = [
                '*'
            ]
        )

        iamperm = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions=[
                'iam:GetRole'
            ],
            resources = [
                'arn:aws:iam::*:role/aws-service-role/application-signals.cloudwatch.amazonaws.com/AWSServiceRoleForCloudWatchApplicationSignals'
            ]
        )

        lambdaperm = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions=[
                'lambda:InvokeFunction'
            ],
            resources = [
                'arn:aws:lambda:'+region+':'+account+':function:walleye',
                'arn:aws:lambda:'+region+':'+account+':function:perch',
                'arn:aws:lambda:'+region+':'+account+':function:northern',
                'arn:aws:lambda:'+region+':'+account+':function:pike'
            ]
        )

        oamperm = _iam.PolicyStatement(
            effect = _iam.Effect.ALLOW,
            actions=[
                'oam:ListAttachedLinks'
            ],
            resources = [
                'arn:aws:oam:*:*:sink/*'
            ]
        )

    ### PARAMETERS ###

        workspace = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'workspace',
            parameter_name = '/slack/4n6ir'
        )

        channellunkerzero = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'channellunkerzero',
            parameter_name = '/slack/lunkerzero'
        )

        channellunker = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'channellunker',
            parameter_name = '/slack/lunker'
        )

    ### CHATBOT LUNKERZERO ###

        slacklunkerzero = _chatbot.SlackChannelConfiguration(
            self, 'slacklunkerzero',
            logging_level = _chatbot.LoggingLevel.INFO,
            slack_channel_configuration_name = 'lunkerzero',
            slack_workspace_id = workspace.string_value,
            slack_channel_id = channellunkerzero.string_value
        )

        slacklunkerzero.add_to_role_policy(cwlperm)
        slacklunkerzero.add_to_role_policy(iamperm)
        slacklunkerzero.add_to_role_policy(oamperm)

        topiclunkerzero = _sns.Topic(
            self, 'topiclunkerzero',
            display_name = 'lunkerzero',
            topic_name = 'lunkerzero'
        )

        slacklunkerzero.add_notification_topic(topiclunkerzero)

        slacklunkerzero.apply_removal_policy(
            RemovalPolicy.DESTROY    
        )

    ### CHATBOT LUNKER ###

        slacklunker = _chatbot.SlackChannelConfiguration(
            self, 'slacklunker',
            logging_level = _chatbot.LoggingLevel.INFO,
            slack_channel_configuration_name = 'lunker',
            slack_workspace_id = workspace.string_value,
            slack_channel_id = channellunker.string_value
        )

        slacklunker.add_to_role_policy(lambdaperm)

        topiclunker = _sns.Topic(
            self, 'topiclunker',
            display_name = 'lunker',
            topic_name = 'lunker'
        )

        slacklunker.add_notification_topic(topiclunker)

        slacklunker.apply_removal_policy(
            RemovalPolicy.DESTROY    
        )
