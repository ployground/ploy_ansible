from mock import MagicMock
import pytest


class MockRunner:
    pass


@pytest.fixture
def runner():
    return MockRunner()


@pytest.fixture
def conn(ctrl, ployconf, runner):
    from ploy_ansible.execnet_connection import Connection
    ctrl.configfile = ployconf.path
    runner._ploy_ctrl = ctrl
    connection = Connection(runner, 'foo', 87, 'blubber', None, None)
    return connection


@pytest.fixture
def rpc():
    class RPC:
        def exec_command(self, cmd):
            return (0, cmd, '')
    return RPC()


def test_execnet_connection(ctrl, monkeypatch):
    import tempfile
    init_ssh_key_mock = MagicMock()
    init_ssh_key_mock.return_value = dict()
    monkeypatch.setattr(
        "ploy.tests.dummy_plugin.Instance.init_ssh_key", init_ssh_key_mock)
    makegateway_mock = MagicMock()
    monkeypatch.setattr("execnet.makegateway", makegateway_mock)
    channel_mock = makegateway_mock().remote_exec()
    channel_mock.receive.side_effect = [
        (0, ctrl.configpath, ''),
        None,
        (0, '{}', '')]
    monkeypatch.setattr("sys.stdin", tempfile.TemporaryFile())
    ctrl(['./bin/ploy', 'ansible', 'default-foo', '-a', 'ls'])
    assert [x[0][0][0] for x in channel_mock.send.call_args_list] == [
        'exec_command', 'put_file', 'exec_command']
    assert [x[0][0][2] for x in channel_mock.send.call_args_list] == [
        {}, {}, {}]
    assert 'mkdir' in channel_mock.send.call_args_list[0][0][0][1][0]
    assert 'CommandModule' in channel_mock.send.call_args_list[1][0][0][1][0]


@pytest.mark.parametrize("ssh_info, expected", [
    (dict(host='foo'), ['foo']),
    (dict(host='foo', port=22), ['-p', '22', 'foo']),
    (dict(host='foo', port=22, ProxyCommand='ssh master -W 10.0.0.1'),
     ['-o', 'ProxyCommand=ssh master -W 10.0.0.1', '-p', '22', 'foo'])])
def test_execnet_ssh_spec(conn, ctrl, ployconf, runner, monkeypatch, ssh_info, expected):
    runner.inventory = MagicMock()
    init_ssh_key_mock = MagicMock()
    init_ssh_key_mock.return_value = ssh_info
    monkeypatch.setattr("ploy_ansible.execnet_connection.RPC_CACHE", {})
    monkeypatch.setattr(
        "ploy.tests.dummy_plugin.Instance.init_ssh_key", init_ssh_key_mock)
    makegateway_mock = MagicMock()
    monkeypatch.setattr("execnet.makegateway", makegateway_mock)
    conn.connect()
    call, = makegateway_mock.call_args_list
    spec = call[0][0]
    assert spec.ssh.split() == expected


class ExecCommandBase:
    def test_exec_command(self, conn, rpc, runner):
        conn.rpc = rpc
        assert conn.exec_command('cmd', 'tmp', None, sudoable=False, executable=None) == (
            0, '', 'cmd', '')
        assert conn.exec_command('cmd', 'tmp', None, sudoable=True, executable=None) == (
            0, '', 'cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=False, executable=None) == (
            0, '', 'cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=True, executable=None) == (
            0, '', 'cmd', '')

    def test_exec_command_executable(self, conn, rpc, runner):
        conn.rpc = rpc
        assert conn.exec_command('cmd', 'tmp', None, sudoable=False, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')
        assert conn.exec_command('cmd', 'tmp', None, sudoable=True, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=False, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=True, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')

    def test_exec_command_sudo(self, conn, rpc, runner):
        conn.rpc = rpc
        runner.sudo = True
        assert conn.exec_command('cmd', 'tmp', None, sudoable=False, executable=None) == (
            0, '', 'cmd', '')
        assert conn.exec_command('cmd', 'tmp', None, sudoable=True, executable=None) == (
            0, '', 'sudo None None cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=False, executable=None) == (
            0, '', 'cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=True, executable=None) == (
            0, '', 'sudo None user cmd', '')

    def test_exec_command_sudo_executable(self, conn, rpc, runner):
        conn.rpc = rpc
        runner.sudo = True
        assert conn.exec_command('cmd', 'tmp', None, sudoable=False, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')
        assert conn.exec_command('cmd', 'tmp', None, sudoable=True, executable='/bin/sh') == (
            0, '', 'sudo /bin/sh None cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=False, executable='/bin/sh') == (
            0, '', '/bin/sh -c cmd', '')
        assert conn.exec_command('cmd', 'tmp', 'user', sudoable=True, executable='/bin/sh') == (
            0, '', 'sudo /bin/sh user cmd', '')


class TestAnsible14(ExecCommandBase):
    @pytest.fixture
    def runner(self, monkeypatch, runner):
        def make_sudo_cmd(sudo_user, executable, cmd):
            return 'sudo %s %s %s' % (executable, sudo_user, cmd), 'prompt', 'key'
        monkeypatch.setattr("ansible.utils.make_sudo_cmd", make_sudo_cmd)
        runner.sudo = False
        return runner


class TestAnsible18(ExecCommandBase):
    @pytest.fixture
    def runner(self, monkeypatch, runner):
        def make_sudo_cmd(sudo_exe, sudo_user, executable, cmd):
            return '%s %s %s %s' % (sudo_exe, executable, sudo_user, cmd), 'prompt', 'key'
        monkeypatch.setattr("ansible.utils.make_sudo_cmd", make_sudo_cmd)
        runner.sudo = False
        runner.sudo_exe = 'sudo'
        return runner


class TestAnsible19(ExecCommandBase):
    @pytest.fixture
    def runner(self, monkeypatch, runner):
        import ansible.utils

        def make_become_cmd(cmd, user, shell, method, flags=None, exe=None):
            return '%s %s %s %s' % (method, shell, user, cmd), 'prompt', 'key'

        monkeypatch.setattr(ansible.utils, "make_become_cmd", make_become_cmd, raising=False)
        runner.sudo = False
        runner.become_exe = 'sudo'
        runner.become_method = 'sudo'
        return runner
