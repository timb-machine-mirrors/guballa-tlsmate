import abc
from pathlib import Path
import dill as pickle
from tlsmate.dependency_injection import Container, providers
from tlsmate import utils


class TlsSuite(metaclass=abc.ABCMeta):
    """Provides a base class for the implementation of test suites.

    Attributes:
        server_profile (:obj:`tlsmate.server_profile.ServerProfile`): The server
            profile instance. Can be used to get data from it (e.g. which cipher
            suites are supported for which TLS versions), or to extend it.
        client (:obj:`tlsmate.client.Client`): The client object.
    """

    prio = 100

    def __init__(self, server_profile=None, client=None):
        self.server_profile = server_profile
        self.client = client

    def _inject_dependencies(self, server_profile, client):
        """Method to inject the server profile and the client into the object
        """
        self.server_profile = server_profile
        self.client = client

    @abc.abstractmethod
    def run(self):
        """Entry point for the test suite.

        The test manager will call this method which will implement the test suite.
        """
        raise NotImplementedError


class TlsSuiteTester(metaclass=abc.ABCMeta):
    """Base class to define unit tests
    """

    recorder_pickle = None
    sp_in_pickle = None
    sp_out_pickle = None
    path = None
    server = None
    port = None

    def get_pickle_file(self, name):
        """Determine the file where an object is serialized to.

        :return: a Path object for the pickle file
        :rtype: :class:`pathlib.Path`
        """
        return self.path.resolve().parent / "recordings" / (name + ".pickle")

    def pickle_obj(self, obj, name):
        file_name = self.get_pickle_file(name)
        if file_name.exists():
            print(f"File {file_name} existing. Pickle file not generated")
            return
        with open(file_name, "wb") as fd:
            pickle.dump(obj, fd)

    def unpickle_obj(self, name):
        with open(self.get_pickle_file(name), "rb") as fd:
            return pickle.load(fd)

    def entry(self, is_replaying=False):
        """Bla bla
        """
        container_args = {}

        if is_replaying and self.recorder_pickle is not None:
            recorder = self.unpickle_obj(self.recorder_pickle)
            recorder.replay()
            container_args["recorder"] = providers.Object(recorder)
        if self.sp_in_pickle is not None:
            server_profile = self.unpickle_obj(self.sp_in_pickle)
            container_args["server_profile"] = providers.Object(server_profile)

        container = Container(**container_args)

        ini_file = Path.home() / ".tlsmate.ini"
        if not ini_file.is_file():
            ini_file = Path.cwd() / ".tlsmate.ini"

        config = container.config(ini_file=ini_file)
        config.merge_config("server", self.server)
        config.merge_config("port", self.port)
        config.merge_config("progress", False)

        utils.set_logging(config["logging"])

        if not is_replaying:
            container.recorder().record()

        self.run(container, is_replaying)

        if not is_replaying:
            if self.recorder_pickle is not None:
                recorder = container.recorder()
                self.pickle_obj(recorder, self.recorder_pickle)
            if self.sp_out_pickle is not None:
                server_profile = container.server_profile()
                self.pickle_obj(server_profile, self.sp_out_pickle)

    def test_entry(self):
        self.entry(is_replaying=True)
