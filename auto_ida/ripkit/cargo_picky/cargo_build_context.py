'''
File to better handle built cargo binaries, build context, and source
'''

import os 
import json



from pathlib import Path



# Save source of every package version? 




# Context to save with each pkg 
#  -  Release version
# 
# 
# 



# cargo version 
# toolchain used 
#   - version of each tool in chain 
# rustc version 
# flags at each lvl of toolchain 
# ?? version of target, through cross or cargo itself ??



import subprocess




def get_cargo_version():
    try:
        rust_version = subprocess.check_output(["cargo", "--version"], stderr=subprocess.STDOUT, text=True)
        return rust_version.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.strip()}"


def get_rust_version():
    try:
        rust_version = subprocess.check_output(["rustc", "--version"], stderr=subprocess.STDOUT, text=True)
        return rust_version.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.strip()}"


def get_cargo_metadata(manifest_path = Path("Cargo.toml")):
    try:
        cargo_metadata_command = ["cargo", "metadata", "--manifest-path", manifest_path.resolve(), "--format-version=1", "--all-features", "-vv"]
        cargo_metadata_output = subprocess.check_output(cargo_metadata_command, stderr=subprocess.STDOUT, text=True)
        cargo_metadata_json = json.loads(cargo_metadata_output.strip())
    except subprocess.CalledProcessError as e:
        return {} 
    return cargo_metadata_json
 

def get_cargo_build_steps(manifest_path = Path("Cargo.toml")):
    cargo_metadata_json = get_cargo_metadata(manifest_path)
    if cargo_metadata_json == {}:
        return {}

    build_steps = []
    for line in cargo_metadata_json.get("reason", []):
        if line["reason"] == "compiler-artifact":
            build_steps.append(line["message"]["command"])

    return build_steps


if __name__ == "__main__":

    tmp_pkg = Path("~/.cargo_reg/cargo_cloned/pyre/Cargo.toml").expanduser()

    pkg_metadata = get_cargo_metadata(tmp_pkg)
    print(f"Metadata... {len(pkg_metadata.keys())}")
    print(f" Keys... {pkg_metadata.keys()}")

    rust_version = get_rust_version()
    print("Installed Rust version:", rust_version)

    cargo_version = get_cargo_version()
    print("Installed Cargo version:", cargo_version)




