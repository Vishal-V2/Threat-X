from functools import lru_cache

import yaml

from common.paths import CONFIG_DIR


@lru_cache(maxsize=None)
def load_yaml(name: str) -> dict:
    """Load and cache a YAML file from config/ by filename, e.g. load_yaml('scoring.yaml')."""
    with open(CONFIG_DIR / name) as f:
        return yaml.safe_load(f)


def scoring_config() -> dict:
    return load_yaml("scoring.yaml")


def assets_config() -> dict:
    return load_yaml("assets.yaml")


def suppressions_config() -> dict:
    return load_yaml("suppressions.yaml")
