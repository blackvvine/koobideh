import os
import yaml

_current_dir = os.path.dirname(os.path.realpath(__file__))
_yaml_conf = yaml.load(open(os.path.join(_current_dir, "config.yml")))

FEATURE_SIZE = _yaml_conf["max_packets_in_flow"]

PARTITIONS = _yaml_conf["partitions"]

MASK_IP = _yaml_conf["mask_ip"]
MASK_PORT = _yaml_conf["mask_port"]

CLASSES = _yaml_conf["labels"]

