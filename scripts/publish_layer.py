#!/usr/bin/env python3
"""
Publish package as Lambda Layer
"""

import argparse
import os
import subprocess
import boto3
import shutil


def run_command(cmd, cwd=None):
    ret = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        cwd=cwd)
    if ret.returncode:
        raise RuntimeError(
            "Running {} failed!\n Output: {}".format(
                cmd, ret.stdout.decode("utf-8")))
    return ret.stdout.decode("utf-8")


PROJECT_ROOT = os.path.abspath(
    os.path.dirname(os.path.dirname(__file__)))

TMP_FOLDER = os.path.join(PROJECT_ROOT, "tmp_layers")
LAYER_FOLDER = os.path.join(PROJECT_ROOT, "layers")
LAYER_PATTERN = "faas_profiler_python-{platform}-py{version}-{implementation}.zip"


parser = argparse.ArgumentParser(
    description="Publish FaaS-Profiler-Python Layer")
parser.add_argument("--python-version", type=str, default="3.8")
parser.add_argument("--implementation", type=str, default="cp")
parser.add_argument("--platform", type=str, default="manylinux2014_x86_64")

args = parser.parse_args()
print(args)

print(f"Creating tmp folder {TMP_FOLDER}")
os.makedirs(TMP_FOLDER, exist_ok=True)

print(f"Creating layers folder {LAYER_FOLDER}")
os.makedirs(LAYER_FOLDER, exist_ok=True)

_target = os.path.join(
    TMP_FOLDER,
    "python",
    "lib",
    f"python{args.python_version}",
    "site-packages")
print(f"Install package in {_target}")
try:
    run_command(
        "pip install "
        f"--platform {args.platform} "
        f"--target={_target} "
        f"--implementation {args.implementation} "
        f"--python {args.python_version} "
        "--only-binary=:all: --upgrade "
        ".")

    _zip_file = LAYER_PATTERN.format(
        platform=args.platform,
        version=args.python_version,
        implementation=args.implementation)
    _full_zip_path = os.path.join(LAYER_FOLDER, _zip_file)
    print(f"Create zip package {_full_zip_path}")
    run_command(f"cd {TMP_FOLDER} && zip -r {_full_zip_path} .")
finally:
    print(f"Remove folder {TMP_FOLDER}")
    shutil.rmtree(TMP_FOLDER)


print("Publish layer to AWS Lambda")
client = boto3.client("lambda", region_name="eu-central-1")

with open(_full_zip_path, "rb") as f:
    _zip_bytes = f.read()

response = client.publish_layer_version(
    LayerName='faas_profiler_python',
    Content={'ZipFile': _zip_bytes},
    CompatibleRuntimes=[f"python{args.python_version}"],
    CompatibleArchitectures=['x86_64']
)

_version = response.get("Version")
print(f"Published layer Version {_version}")
