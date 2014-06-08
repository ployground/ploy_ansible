from mock import patch
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
    assert 'parse error: playbooks must be formatted as a YAML list, got' in call_args[0]


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
    monkeypatch.setattr("ansible.playbook.PlayBook.run", lambda s: 0 / 0)
    with pytest.raises(ZeroDivisionError):
        aws(['./bin/aws', 'configure', 'foo'])
