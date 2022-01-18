# -*- coding: utf-8 -*-
"""Module for defining an environment for tlsmate.

This can be seen as a collection of sigletons.
"""
# import basic stuff
from typing import NamedTuple

# import own stuff
import tlsmate.client_auth as client_auth
import tlsmate.config as conf
import tlsmate.crl_manager as crl_manager
import tlsmate.recorder as rec
import tlsmate.resolver as resolver
import tlsmate.server_profile as server_profile
import tlsmate.trust_store as trust_store


class Platform(NamedTuple):
    """Collection of some common objects.
    """

    client_auth: client_auth.ClientAuth
    config: conf.Configuration
    crl_manager: crl_manager.CrlManager
    recorder: rec.Recorder
    resolver: resolver.Resolver
    server_profile: server_profile.ServerProfile
    trust_store: trust_store.TrustStore
