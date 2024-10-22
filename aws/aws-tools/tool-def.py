import inspect

from kubiya_sdk import tool_registry
from kubiya_sdk.tools.models import Arg, Tool, FileSpec

from . import aws

aws_tool = Tool(
    name="aws",
    description="You are an intelligent tool designed to interact with AWS services. Your default environment is dev and your default action is list_s3_buckets.",
    type="docker",
    image="python:3.11-bullseye",
    args=[],
    secrets=[],
    env=["AWS_PROFILE"],
    content="""
pip install boto3 > /dev/null 2>&1

python /tmp/aws.py
""",
    with_files=[
        FileSpec(
            destination="/tmp/aws.py",
            content=inspect.getsource(aws),
        ),
        FileSpec(
            destination="/root/.aws/credentials",
            source="$HOME/.aws/credentials",
        ),
        FileSpec(
            destination="/root/.aws/config",
            source="$HOME/.aws/config",
        )
    ]
)

tool_registry.register("aedm", aws_tool)
