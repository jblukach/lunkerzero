#!/usr/bin/env python3
import os

import aws_cdk as cdk

from lunkerzero.lunkerzero_development import LunkerzeroDevelopment
from lunkerzero.lunkerzero_guineapigs import LunkerzeroGuineapigs
from lunkerzero.lunkerzero_inspection import LunkerzeroInspection
from lunkerzero.lunkerzero_production import LunkerzeroProduction
from lunkerzero.lunkerzero_stack import LunkerzeroStack
from lunkerzero.lunkerzero_verification import LunkerzeroVerification

app = cdk.App()

LunkerzeroDevelopment(
    app, 'LunkerzeroDevelopment',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

LunkerzeroGuineapigs(
    app, 'LunkerzeroGuineapigs',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

LunkerzeroInspection(
    app, 'LunkerzeroInspection',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

LunkerzeroProduction(
    app, 'LunkerzeroProduction',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

LunkerzeroStack(
    app, 'LunkerzeroStack',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

LunkerzeroVerification(
    app, 'LunkerzeroVerification',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

cdk.Tags.of(app).add('Alias','4n6ir')
cdk.Tags.of(app).add('GitHub','https://github.com/jblukach/lunkerzero')

app.synth()