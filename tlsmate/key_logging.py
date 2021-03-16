# -*- coding: utf-8 -*-
"""Module for logging to a key log file

Reference: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
"""
# import basic stuff

# import own stuff

# import other stuff

class KeyLogger(object):
    """Class to log to a key log file
    """

    _fd = None

    @classmethod
    def open_file(cls, file_name):
        cls._fd = open(file_name, "a")

    @classmethod
    def close(cls):
        cls._fd.close()

    @classmethod
    def _log(cls, log_type, client_random, secret):
        if cls._fd:
            cls._fd.write(f"{log_type} {client_random.hex()} {secret.hex()}\n")
            cls._fd.flush()

    @classmethod
    def master_secret(cls, client_random, secret):
        cls._log("CLIENT_RANDOM", client_random, secret)

    @classmethod
    def client_early_tr_secret(cls, client_random, secret):
        cls._log("CLIENT_EARLY_TRAFFIC_SECRET", client_random, secret)

    @classmethod
    def client_hs_tr_secret(cls, client_random, secret):
        cls._log("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, secret)

    @classmethod
    def server_hs_tr_secret(cls, client_random, secret):
        cls._log("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, secret)

    @classmethod
    def client_tr_secret_0(cls, client_random, secret):
        cls._log("CLIENT_TRAFFIC_SECRET_0", client_random, secret)

    @classmethod
    def server_tr_secret_0(cls, client_random, secret):
        cls._log("SERVER_TRAFFIC_SECRET_0", client_random, secret)
