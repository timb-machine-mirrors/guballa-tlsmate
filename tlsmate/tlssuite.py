import abc
from pathlib import Path
import yaml
from tlsmate.dependency_injection import Container
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

    recorder_yaml = None
    sp_in_yaml = None
    sp_out_yaml = None
    path = None
    server = None
    port = None

    def get_yaml_file(self, name):
        """Determine the file where an object is serialized to.

        Arguments:
            name (str): the basic name of the file, without directory and without
                the suffix

        Returns:
            :class:`pathlib.Path`: a Path object for the yaml file
        """
        return self.path.resolve().parent / "recordings" / (name + ".yaml")

    def serialize(self, obj, name):
        """Dump the object to a yaml file.

        Arguments:
            obj (dict): the object to serialize
            name (str): the file name (without directory and suffix) to write the
                serialized object to
        """
        file_name = self.get_yaml_file(name)
        if file_name.exists():
            print(f"File {file_name} existing. Yaml file not generated")
            return
        with open(file_name, "w") as fd:
            yaml.dump(obj, fd)

    def deserialize(self, name):
        """Deserialize a yaml file.

        Arguments:
            name (str): the full file name

        Returns:
            object: the deserialized object
        """
        with open(self.get_yaml_file(name)) as fd:
            return yaml.safe_load(fd)

    def entry(self, is_replaying=False):
        """Entry point for a test case.

        Arguments:
            is_replaying (bool): an indication if the test case is replayed or recorded.
                Defaults to False.
        """
        container = Container()
        recorder = container.recorder()
        profile = container.server_profile()

        if is_replaying and self.recorder_yaml is not None:
            recorder.deserialize(self.get_yaml_file(self.recorder_yaml))
            recorder.replay()
        if self.sp_in_yaml is not None:
            data = self.deserialize(self.sp_in_yaml)
            profile.load(data)

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
            if self.recorder_yaml is not None:
                recorder.serialize(self.get_yaml_file(self.recorder_yaml))
            if self.sp_out_yaml is not None:
                self.serialize(profile.make_serializable(), self.sp_out_yaml)

    def test_entry(self):
        """Entry point for pytest.
        """
        self.entry(is_replaying=True)
