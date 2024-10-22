import inspect

from kubiya_sdk import tool_registry
from kubiya_sdk.tools.models import Arg, Tool, FileSpec

from . import fake_tool, wireguard_update

fake_tool = Tool(
    name="fake-tool",
    description="This is a fake tool",
    type="docker",
    image="python:3.11-bullseye",
    args=[],
    secrets=[],
    env=[],
    content="""
    python /tmp/fake_tool.py
    """,
    with_files=[
        FileSpec(
            destination="/tmp/fake_tool.py",
            content=inspect.getsource(fake_tool),
        ),
    ]
)

wireguard_update_tool = Tool(
    name="wireguard_update",
    description="You are an intelligent tool designed check for AMI updates for Wireguard. Your default environment is dev and your default action is check.",
    type="docker",
    image="python:3.11-bullseye",
    args=[
        Arg(
            name="action",
            required=True,
            description="check or update, Check will only scan for updates and update will update the AMI.",
            default= "check",
        ),
        Arg(
            name="environment",
            required=True,
            description="Environment to check or update against. Accepted values are 'dev' or 'prod'. If no value is provided, 'dev' should be used as the default.",
            default = "dev",
        ),
    ],
    secrets=["TOOLS_GH_TOKEN", "GH_TOKEN"],
    env=["AWS_PROFILE"],
    content="""
pip install boto3 > /dev/null 2>&1
pip install requests > /dev/null 2>&1
pip install argparse > /dev/null 2>&1

echo "Passed action: $action"
echo "Passed environment: $environment"


python /tmp/wireguard_update.py --action "$action" --environment "$environment" 
""",
    with_files=[
        FileSpec(
            destination="/tmp/wireguard_update.py",
            content=inspect.getsource(wireguard_update),
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

tool_registry.register("aedm", fake_tool)
tool_registry.register("aedm", wireguard_update_tool)
