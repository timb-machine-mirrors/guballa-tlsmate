# -*- coding: utf-8 -*-
"""Module containing the CLI helpers
"""
# import basic stuff
import argparse

# import own stuff

# import other stuff


class BooleanOptionalAction(argparse.Action):
    """Class to support --flag and --no-flag arguments.

    Will be natively supported by Python3.9
    """

    def __init__(
        self,
        option_strings,
        dest,
        default=None,
        type=None,
        choices=None,
        required=False,
        help=None,
        metavar=None,
    ):

        _option_strings = []
        for option_string in option_strings:
            _option_strings.append(option_string)

            if option_string.startswith("--"):
                option_string = "--no-" + option_string[2:]
                _option_strings.append(option_string)

        if help is not None and default is not None:
            help += f" (default: {default})"

        super().__init__(
            option_strings=_option_strings,
            dest=dest,
            nargs=0,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            setattr(namespace, self.dest, not option_string.startswith("--no-"))

    def format_usage(self):
        return " | ".join(self.option_strings)


def add_basic_arguments(parser):
    """Add basic arguments to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    parser.add_argument(
        "--interval",
        default=0,
        help="the interval in milliseconds between two handshakes.",
        type=int,
    )
    parser.add_argument(
        "--key-log-file",
        default=None,
        help=(
            "write to a key log file which can be used by wireshark to decode "
            "encrypted traffic."
        ),
    )

    parser.add_argument(
        "--progress",
        help="provides a progress indicator",
        action=BooleanOptionalAction,
    )

    parser.add_argument(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of for the server to "
            "contact. If not given, the value will be taken from the host parameter "
            "(after stripping of the port number, if present). This parameter is "
            "useful, if the host is given as an IP address."
        ),
    )

    parser.add_argument(
        "host",
        help=(
            "the host to scan. May optionally have the port number appended, "
            "separated by a colon."
        ),
        type=str,
    )


def add_args_authentication(parser):
    """Add basic arguments for authentication to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    group = parser.add_argument_group(title="X509 certificates options")
    group.add_argument(
        "--ca-certs",
        nargs="*",
        type=str,
        help=(
            "list of root-ca certificate files. Each file may contain multiple "
            "root-CA certificates in PEM format. Certificate chains received from "
            "the server will be validated against this set of root certificates."
        ),
    )

    group.add_argument(
        "--client-key",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the client private keys in PEM format. "
            "Used for client authentication."
        ),
        default=None,
    )
    group.add_argument(
        "--client-chain",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the certificate chain used for client "
            "authentication in PEM format. The number of given files must be the "
            "same than the number of given client key files. This first given "
            "chain file corresponds to the first given client key file, and so on."
        ),
    )

    group.add_argument(
        "--crl",
        help=(
            "download the CRL to check for the certificate revocation status. "
            "Defaults to True."
        ),
        action=BooleanOptionalAction,
    )
    group.add_argument(
        "--ocsp",
        help=(
            "query the OCSP servers for checking the certificate revocation status. "
            "Defaults to True."
        ),
        action=BooleanOptionalAction,
    )


def set_config_basic(config, args):
    """Set the configuration for basic CLI arguments.

    Arguments:
        config (:obj:`tlsmate.config.Configuration`): the configuration object
        args: object with the parsed arguments
    """

    config.set("progress", args.progress)
    config.set("interval", args.interval)
    config.set("endpoint", args.host)
    config.set("sni", args.sni)
    config.set("key_log_file", args.key_log_file)


def set_config_authentication(config, args):
    """Set the configuration for CLI arguments related to authentication.

    Arguments:
        config (:obj:`tlsmate.config.Configuration`): the configuration object
        args: object with the parsed arguments
    """

    config.set("ca_certs", args.ca_certs)
    config.set("client_key", args.client_key)
    config.set("client_chain", args.client_chain)
    config.set("crl", args.crl)
    config.set("ocsp", args.ocsp)
