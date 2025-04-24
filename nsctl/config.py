import os
from pydantic import BaseModel, Field
from typing import Literal, Annotated


ns_config_base_path = "/tmp/nsctl"


# Grouped Namespace information for serialization
class Namespaces(BaseModel):
    net: bool
    mount: bool
    pid: bool
    ipc: bool
    uts: bool
    user: bool
    cgroup: bool
    time: bool


class NetMacvlan(BaseModel):
    kind: Literal["macvlan"]
    host_if: str
    name: str
    ip: str


class NetHostForward(BaseModel):
    kind: Literal["host_forward"]
    host_ip: str
    ns_ip: str
    port: str # Can be a range as well


NetItem = Annotated[
    NetMacvlan | NetHostForward,
    Field(discriminator="kind")
]


class NSInfo(BaseModel):
    name: str
    pid: int
    namespaces: Namespaces
    net: list[NetItem] = Field(default_factory=list)


def load_namespace_config(ns_name: str) -> NSInfo:
    """Load the namespace configuration from the file. If it can't, it will throw an exception"""
    config_path = os.path.join(
        ns_config_base_path,
        ns_name,
        "configuration.conf"
    )

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file for namespace {ns_name} not found at {config_path}")
    with open(config_path) as f:
        return NSInfo.model_validate_json(f.read())


def save_namespace_config(ns_name: str, config: NSInfo):
    config_path = os.path.join(
        ns_config_base_path,
        ns_name,
        "configuration.conf"
    )
    with open(config_path, "w") as f:
        _ = f.write(config.model_dump_json(indent=2))
