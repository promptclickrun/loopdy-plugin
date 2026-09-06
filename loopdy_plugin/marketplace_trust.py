"""Public trust anchors for releases from the Loopdy marketplace.

Only public Ed25519 keys belong here. An explicit environment override replaces
this set, including an empty string to disable marketplace release trust.
"""
PRODUCTION_RELEASE_KEYS = {
    "loopdy-release-2026-09": "GnPP7wB2Le94RCGEzcDCa+SNzc/6i2Ftgox92cHhzGQ=",
}
