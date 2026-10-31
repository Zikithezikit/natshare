"""Constants shared across modules."""

DEFAULT_SUBNET = "10.42.0.0/24"
GATEWAY_OFFSET = 1  # gateway is the first host address in the client subnet
MAX_PREFIXLEN = 27  # smallest supported client subnet is a /27
