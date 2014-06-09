from mock import MagicMock, patch
import os
import pytest
import shutil
import tempfile


def test_register_ansible_module_path():
    pass


def test_register_ansible_module_path_from_multiple_entry_points():
    pass


@pytest.yield_fixture
def aws():
    from mr.awsome import AWS
    import mr.awsome_ansible
    import mr.awsome.tests.dummy_plugin
    directory = tempfile.mkdtemp()
    configfile = os.path.join(directory, 'aws.conf')
    with open(configfile, 'w') as f:
        f.write('\n'.join([
            '[dummy-instance:foo]']))
    aws = AWS(configpath=directory)
    aws.plugins = {
        'dummy': mr.awsome.tests.dummy_plugin.plugin,
        'ansible': mr.awsome_ansible.plugin}
    yield aws
    shutil.rmtree(directory)


def test_configure_without_args(aws):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'configure'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: aws configure' in output
    assert 'too few arguments' in output


def test_configure_with_nonexisting_instance(aws):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'configure', 'bar'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: aws configure' in output
    assert "argument instance: invalid choice: 'bar'" in output


def test_configure_with_missing_yml(aws):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'configure', 'foo'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: aws configure' in output
    assert "argument instance: invalid choice: 'foo'" in output


def test_configure_with_empty_yml(aws):
    with open(os.path.join(aws.configpath, 'foo.yml'), 'w') as f:
        f.write('\n'.join([
            '']))
    with patch('mr.awsome_ansible.log') as LogMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'configure', 'foo'])
    assert len(LogMock.error.call_args_list) == 1
    call_args = LogMock.error.call_args_list[0][0]
    assert 'parse error: playbooks must be formatted as a YAML list' in call_args[0]


def test_configure_asks_when_no_host_in_yml(aws):
    yml = os.path.join(aws.configpath, 'foo.yml')
    with open(yml, 'w') as f:
        f.write('\n'.join([
            '---',
            '- {}']))
    with patch('mr.awsome_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'configure', 'foo'])
    assert len(YesNoMock.call_args_list) == 1
    call_args = YesNoMock.call_args_list[0][0]
    assert "Do you really want to apply '%s' to the host '%s'?" % (yml, 'foo') in call_args[0]


def test_configure(aws, monkeypatch):
    with open(os.path.join(aws.configpath, 'foo.yml'), 'w') as f:
        f.write('\n'.join([
            '---',
            '- hosts: foo']))
    runmock = MagicMock()
    monkeypatch.setattr("ansible.playbook.PlayBook.run", runmock)
    aws(['./bin/aws', 'configure', 'foo'])
    assert runmock.called


def test_playbook_without_args(aws):
    with patch('sys.stderr') as StdErrMock:
        StdErrMock.encoding = 'utf-8'
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'playbook'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'Usage: aws playbook playbook.yml' in output


def test_playbook_with_nonexisting_playbook(aws):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'playbook', 'bar.yml'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert "the playbook: bar.yml could not be found" in output


def test_playbook_with_empty_yml(aws):
    yml = os.path.join(aws.configpath, 'foo.yml')
    with open(yml, 'w') as f:
        f.write('\n'.join([
            '']))
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'playbook', yml])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'parse error: playbooks must be formatted as a YAML list' in output


def test_playbook_asks_when_no_host_in_yml(aws):
    yml = os.path.join(aws.configpath, 'foo.yml')
    with open(yml, 'w') as f:
        f.write('\n'.join([
            '---',
            '- {}']))
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'playbook', yml])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'hosts declaration is required' in output


def test_playbook(aws, monkeypatch):
    yml = os.path.join(aws.configpath, 'foo.yml')
    with open(yml, 'w') as f:
        f.write('\n'.join([
            '---',
            '- hosts: foo']))
    runmock = MagicMock()
    monkeypatch.setattr("ansible.playbook.PlayBook.run", runmock)
    aws(['./bin/aws', 'playbook', yml])
    assert runmock.called


def test_ansible_without_args(aws):
    with patch('sys.stdout') as StdOutMock:
        StdOutMock.encoding = 'utf-8'
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'ansible'])
    output = "".join(x[0][0] for x in StdOutMock.write.call_args_list)
    assert 'Usage: aws ansible' in output


def test_ansible_with_nonexisting_instance(aws):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            aws(['./bin/aws', 'ansible', 'bar'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert "No hosts matched" in output


def test_ansible(aws, monkeypatch):
    runmock = MagicMock()
    monkeypatch.setattr("ansible.runner.Runner.run", runmock)
    runmock.return_value = dict(
        contacted=dict(),
        dark=[])
    aws(['./bin/aws', 'ansible', 'foo', '-a', 'ls'])
    assert runmock.called


def test_execnet_connection(aws, monkeypatch):
    init_ssh_key_mock = MagicMock()
    init_ssh_key_mock.return_value = dict()
    monkeypatch.setattr(
        "mr.awsome.tests.dummy_plugin.Instance.init_ssh_key", init_ssh_key_mock)
    makegateway_mock = MagicMock()
    monkeypatch.setattr("execnet.makegateway", makegateway_mock)
    channel_mock = makegateway_mock().remote_exec()
    channel_mock.receive.side_effect = [
        (0, aws.configpath, ''),
        None,
        (0, '{}', '')]
    monkeypatch.setattr("sys.stdin", tempfile.TemporaryFile())
    aws(['./bin/aws', 'ansible', 'foo', '-a', 'ls'])
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
def test_execnet_ssh_spec(aws, monkeypatch, ssh_info, expected):
    from mr.awsome_ansible.execnet_connection import Connection
    runner = MagicMock()
    aws.configfile = os.path.join(aws.configpath, aws.configname)
    runner._awsome_aws = aws
    init_ssh_key_mock = MagicMock()
    init_ssh_key_mock.return_value = ssh_info
    monkeypatch.setattr("mr.awsome_ansible.execnet_connection.RPC_CACHE", {})
    monkeypatch.setattr(
        "mr.awsome.tests.dummy_plugin.Instance.init_ssh_key", init_ssh_key_mock)
    makegateway_mock = MagicMock()
    monkeypatch.setattr("execnet.makegateway", makegateway_mock)
    connection = Connection(runner, 'foo', 87, 'blubber', None, None)
    connection.connect()
    call, = makegateway_mock.call_args_list
    spec = call[0][0]
    assert spec.ssh.split() == expected
