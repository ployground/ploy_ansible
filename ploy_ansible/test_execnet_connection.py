from mock import MagicMock
import pytest


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
def test_execnet_ssh_spec(ctrl, ployconf, monkeypatch, ssh_info, expected):
    from ploy_ansible.execnet_connection import Connection
    runner = MagicMock()
    ctrl.configfile = ployconf.path
    runner._ploy_ctrl = ctrl
    init_ssh_key_mock = MagicMock()
    init_ssh_key_mock.return_value = ssh_info
    monkeypatch.setattr("ploy_ansible.execnet_connection.RPC_CACHE", {})
    monkeypatch.setattr(
        "ploy.tests.dummy_plugin.Instance.init_ssh_key", init_ssh_key_mock)
    makegateway_mock = MagicMock()
    monkeypatch.setattr("execnet.makegateway", makegateway_mock)
    connection = Connection(runner, 'foo', 87, 'blubber', None, None)
    connection.connect()
    call, = makegateway_mock.call_args_list
    spec = call[0][0]
    assert spec.ssh.split() == expected
