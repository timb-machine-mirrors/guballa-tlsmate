# -*- coding: utf-8 -*-
"""Helper module for generating and executing test cases
"""

import abc
import pickle
from dependency_injector import providers
import tlsclient.constants as tls
import tlsclient.messages as msg
from tlsclient.dependency_injection import Container


class TcRecorder(metaclass=abc.ABCMeta):
    """An abstract class which allows to generate and execute test cases

    It works by injecting a dedicated recorder object and execute a basic
    handshake scenario.
    """

    # The name of the pickle file. If None, the name is taken from the
    # cipher suite name
    name = None
    path = None
    server = "localhost"
    port = 44330
    cipher_suite = None
    version = tls.Version.TLS12
    openssl_s_server = (
        "export OPENSSL_TRACE=TLS && openssl s_server -key key.pem -cert cert.pem "
        "-accept 44330 -www -trace -cipher ALL"
    )
    supported_groups = [
        tls.SupportedGroups.X25519,
        tls.SupportedGroups.SECP256R1,
        tls.SupportedGroups.SECP384R1,
        tls.SupportedGroups.SECP521R1,
        tls.SupportedGroups.FFDHE2048,
        tls.SupportedGroups.FFDHE4096,
    ]
    signature_algorithms = [
        tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
        tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
        tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
        tls.SignatureScheme.RSA_PKCS1_SHA256,
        tls.SignatureScheme.RSA_PKCS1_SHA384,
        tls.SignatureScheme.RSA_PKCS1_SHA512,
        tls.SignatureScheme.ECDSA_SHA1,
        tls.SignatureScheme.RSA_PKCS1_SHA1,
    ]

    def get_pickle_file(self):
        """Determine the file where the recorder object is serialized to.

        :return: a Path object for the pickle file
        :rtype: :class:`pathlib.Path`
        """
        if self.name is not None:
            name = self.name
        else:
            name = self.cipher_suite.name

        return self.path.resolve().parent / "recordings" / (name + ".pickle")

    def update_client_profile(self, profile):
        """Used in the test case to initialize the profile
        """
        pass

    def scenario(self, container):
        """The basic scenario to be recorded or replayed.
        """
        client_profile = container.client_profile()

        client_profile.versions = [self.version]
        client_profile.cipher_suites = [self.cipher_suite]
        client_profile.supported_groups = self.supported_groups
        client_profile.signature_algorithms = self.signature_algorithms
        self.update_client_profile(client_profile)

        with client_profile.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            conn.wait(msg.ServerKeyExchange, optional=True)
            conn.wait(msg.ServerHelloDone)
            conn.send(msg.ClientKeyExchange, msg.ChangeCipherSpec, msg.Finished)
            conn.wait(msg.ChangeCipherSpec)
            conn.wait(msg.Finished)
            conn.send(msg.AppData(b"Here are some data!"))
        return conn

    def record_testcase(self):
        """This is the method to be called to record a test case.

        All messages sent and received by the record layer are recorded, as well
        as all the random numbers and the keying material used in the handshake.
        """
        pickle_file = self.get_pickle_file()
        config = {"server": self.server, "port": self.port}
        container = Container(config=config)
        recorder = container.recorder()
        recorder.openssl_s_server = self.openssl_s_server
        recorder.record()
        conn = self.scenario(container)

        if pickle_file.exists():
            print("File {} existing. Testcase not generated".format(pickle_file))
            return conn

        with open(pickle_file, "wb") as fd:
            pickle.dump(conn.recorder, fd)
        return conn

    def test_replay_scenario(self):
        """This is the method called by pytest

        It replays a recorded handshake and checks if the keying material has been
        derived correctly. Additionally each message sent is compared to the recorded
        message. If there is mismatch the test case will fail. Encrypted messages
        are checked as well.
        """
        with open(self.get_pickle_file(), "rb") as fd:
            recorder = pickle.load(fd)
        recorder.replay()
        config = {"server": self.server, "port": self.port}
        container = Container(config=config, recorder=providers.Object(recorder))
        self.scenario(container)
