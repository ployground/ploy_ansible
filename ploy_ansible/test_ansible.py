from __future__ import unicode_literals
from ploy_ansible import ANSIBLE1, ANSIBLE2, ANSIBLE_HAS_CONTEXT
import pytest
import sys


if sys.version_info < (3,):  # pragma: nocover
    too_view_arguments = 'too few arguments'
else:  # pragma: nocover
    too_view_arguments = 'the following arguments are required'


def get_tqm_args(tqm):
    if ANSIBLE_HAS_CONTEXT:
        from ansible import context
        return context.CLIARGS
    else:
        return vars(tqm._options)


@pytest.fixture
def runmock(mock, monkeypatch):
    if ANSIBLE1:
        import ansible.playbook
        with mock.patch.object(ansible.playbook.PlayBook, "run", autospec=True) as runmock:
            yield runmock
    else:
        import ansible.executor.task_queue_manager
        with mock.patch.object(ansible.executor.task_queue_manager.TaskQueueManager, "run", autospec=True) as runmock:
            runmock.return_value = 0
            yield runmock


def test_register_ansible_module_path():
    pass


def test_register_ansible_module_path_from_multiple_entry_points():
    pass


def test_configure_without_args(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure'])
    (out, err) = capsys.readouterr()
    assert 'usage: ploy configure' in err
    assert too_view_arguments in err


def test_configure_with_nonexisting_instance(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'bar'])
    (out, err) = capsys.readouterr()
    assert 'usage: ploy configure' in err
    assert "argument instance: invalid choice: 'bar'" in err


def test_configure_with_missing_yml(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'foo'])
    (out, err) = capsys.readouterr()
    assert 'usage: ploy configure' in err
    assert "argument instance: invalid choice: 'foo'" in err


def test_configure_with_empty_yml(ctrl, mock, tempdir):
    tempdir['default-foo.yml'].fill('')
    with mock.patch('ploy_ansible.log') as LogMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'foo'])
    assert len(LogMock.error.call_args_list) == 1
    call_args = LogMock.error.call_args_list[0][0]
    assert (
        "playbooks must be a list of plays" in call_args[0] or
        "playbooks must be formatted as a YAML list, got <type 'NoneType'>" in call_args[0] or
        "Empty playbook, nothing to do" in call_args[0])


def test_configure_asks_when_no_host_in_yml(ctrl, mock, tempdir):
    yml = tempdir['default-foo.yml']
    yml.fill([
        '---',
        '- {}'])
    with mock.patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'foo'])
    assert len(YesNoMock.call_args_list) == 1
    call_args = YesNoMock.call_args_list[0][0]
    assert "Do you really want to apply '%s' to the host '%s'?" % (yml.path, 'default-foo') in call_args[0]


def test_configure(ctrl, runmock, tempdir):
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called


def test_configure_playbook_option(ctrl, monkeypatch, ployconf, runmock, tempdir):
    from ploy_ansible import get_playbook
    yml = tempdir['default-bar.yml']
    yml.fill([
        '---',
        '- hosts: default-foo'])
    ployconf.fill([
        '[dummy-instance:foo]',
        'host = foo',
        'playbook = %s' % yml.path])
    playbooks = []

    def _get_playbook(self, *args, **kwargs):
        pb = get_playbook(self, *args, **kwargs)
        playbooks.append(pb)
        return pb

    monkeypatch.setattr("ploy_ansible.get_playbook", _get_playbook)
    ctrl(['./bin/ploy', 'configure', 'foo'])
    if ANSIBLE1:
        assert runmock.called
        assert runmock.call_args[0][0].filename == yml.path
    else:
        (pb,) = playbooks
        assert pb._file_name == yml.path


def test_configure_playbook_option_shadowing(ctrl, monkeypatch, ployconf, runmock, caplog, tempdir):
    from ploy_ansible import get_playbook
    yml_foo = tempdir['default-foo.yml']
    yml_foo.fill('')
    yml_bar = tempdir['default-bar.yml']
    yml_bar.fill([
        '---',
        '- hosts: default-foo'])
    ployconf.fill([
        '[dummy-instance:foo]',
        'host = foo',
        'playbook = %s' % yml_bar.path])
    playbooks = []

    def _get_playbook(self, *args, **kwargs):
        pb = get_playbook(self, *args, **kwargs)
        playbooks.append(pb)
        return pb

    monkeypatch.setattr("ploy_ansible.get_playbook", _get_playbook)
    ctrl(['./bin/ploy', 'configure', 'foo'])
    if ANSIBLE1:
        assert runmock.called
        assert runmock.call_args[0][0].filename == yml_bar.path
        assert [x.message for x in caplog.records] == [
            "Instance 'dummy-instance:foo' has the 'playbook' option set, but there is also a playbook at the default location '%s', which differs from '%s'." % (yml_foo.path, yml_bar.path),
            "Using playbook at '%s'." % yml_bar.path]
    else:
        (pb,) = playbooks
        assert pb._file_name == yml_bar.path
        assert [x.message for x in caplog.records] == [
            "Instance 'dummy-instance:foo' has the 'playbook' option set, but there is also a playbook at the default location '%s', which differs from '%s'." % (yml_foo.path, yml_bar.path),
            "Using playbook at '%s'." % yml_bar.path]


def test_configure_roles_option(ctrl, ployconf, runmock, tempdir):
    ployconf.fill([
        '[dummy-instance:foo]',
        'host = foo',
        'roles = ham egg'])
    tempdir['roles/egg/tasks/main.yml'].fill([])
    tempdir['roles/ham/tasks/main.yml'].fill([])
    ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called
    if ANSIBLE1:
        assert runmock.call_args[0][0].filename in (
            "<dynamically generated from ['ham', 'egg']>",
            "<dynamically generated from [u'ham', u'egg']>")
        assert runmock.call_args[0][0].playbook == [{'hosts': ['default-foo'], 'user': 'root', 'roles': ['ham', 'egg']}]
        assert runmock.call_args[0][0].play_basedirs == [tempdir.directory]
    else:
        (call,) = runmock.call_args_list
        play = call[1]['play']
        assert play.hosts == ['default-foo']
        assert play.remote_user == 'root'
        assert [x.get_name() for x in play.get_roles()] == ['ham', 'egg']


def test_configure_roles_default_playbook_conflict(ctrl, ployconf, caplog, tempdir):
    yml = tempdir['default-foo.yml']
    yml.fill('')
    ployconf.fill([
        '[dummy-instance:foo]',
        'host = foo',
        'roles = ham egg'])
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert [x.message for x in caplog.records] == [
        "Using playbook at '%s'." % yml.path,
        "You can't use a playbook and the 'roles' options at the same time for instance 'dummy-instance:foo'."]


def test_configure_roles_playbook_option_conflict(ctrl, ployconf, caplog, tempdir):
    yml = tempdir['default-bar.yml']
    yml.fill([
        '---',
        '- hosts: default-foo'])
    ployconf.fill([
        '[dummy-instance:foo]',
        'playbook = %s' % yml.path,
        'host = foo',
        'roles = ham egg'])
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert [x.message for x in caplog.records] == [
        "Using playbook at '%s'." % yml.path,
        "You can't use a playbook and the 'roles' options at the same time for instance 'dummy-instance:foo'."]


def test_configure_playbook_discovery(ctrl, ployconf, caplog, runmock, tempdir):
    tempdir['foo.yml'].fill('')
    yml = tempdir['default-foo.yml']
    yml.fill([
        '---',
        '- hosts: default-foo'])
    ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called
    assert [x.message for x in caplog.records] == [
        "Using playbook at '%s'." % yml.path]


def test_configure_with_extra_vars(ctrl, runmock, tempdir):
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    ctrl(['./bin/ploy', 'configure', 'foo', '-e', 'foo=bar', '-e', 'bar=foo'])
    assert runmock.called
    if ANSIBLE1:
        assert runmock.call_args[0][0].extra_vars == dict(foo='bar', bar='foo')
    else:
        (call,) = runmock.call_args_list
        play = call[1]['play']
        variables = play.get_variable_manager().get_vars()
        assert variables['foo'] == 'bar'
        assert variables['bar'] == 'foo'


def test_configure_with_tags(ctrl, runmock, tempdir):
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    ctrl(['./bin/ploy', 'configure', 'foo', '-t', 'ham,egg'])
    assert runmock.called
    if ANSIBLE1:
        play = runmock.call_args[0][0]
        assert sorted(play.only_tags) == ['egg', 'ham']
        assert play.skip_tags == []
    else:
        (call,) = runmock.call_args_list
        tqm = call[0][0]
        assert sorted(get_tqm_args(tqm)['tags']) == ['egg', 'ham']
        assert get_tqm_args(tqm)['skip_tags'] == []


def test_configure_with_skip_tags(ctrl, runmock, tempdir):
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    ctrl(['./bin/ploy', 'configure', 'foo', '--skip-tags', 'ham,egg'])
    assert runmock.called
    if ANSIBLE1:
        play = runmock.call_args[0][0]
        assert play.only_tags == ['all']
        assert sorted(play.skip_tags) == ['egg', 'ham']
    else:
        (call,) = runmock.call_args_list
        tqm = call[0][0]
        assert get_tqm_args(tqm)['tags'] == ['all']
        assert sorted(get_tqm_args(tqm)['skip_tags']) == ['egg', 'ham']


def test_playbook_without_args(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'playbook'])
    (out, err) = capsys.readouterr()
    if ANSIBLE1:
        assert 'Usage: ploy playbook playbook.yml' in err
    else:
        assert 'Usage:' in out or 'usage:' in err
        assert '[options] playbook.yml' in out or 'playbook [playbook ...]' in err


def test_playbook_with_nonexisting_playbook(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'playbook', 'bar.yml'])
    (out, err) = capsys.readouterr()
    assert "the playbook: bar.yml could not be found" in err


def test_playbook_with_empty_yml(capsys, ctrl, mock, tempdir):
    yml = tempdir['foo.yml']
    yml.fill('')
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'playbook', yml.path])
    (out, err) = capsys.readouterr()
    assert (
        "playbooks must be a list of plays" in err
        or "playbooks must be formatted as a YAML list, got <type 'NoneType'>" in err
        or "Empty playbook, nothing to do" in err)


def test_playbook_asks_when_no_host_in_yml(capsys, ctrl, mock, tempdir):
    yml = tempdir['foo.yml']
    yml.fill([
        '---',
        '- {}'])
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'playbook', yml.path])
    (out, err) = capsys.readouterr()
    assert (
        "'hosts' is required but was not set" in err or
        'hosts declaration is required' in err)


def test_playbook(ctrl, mock, monkeypatch, runmock, tempdir):
    yml = tempdir['foo.yml']
    yml.fill([
        '---',
        '- hosts: foo'])
    if ANSIBLE2:
        runmock = mock.MagicMock()
        monkeypatch.setattr("ansible.cli.playbook.PlaybookCLI.run", runmock)
        runmock.return_value = 0
    ctrl(['./bin/ploy', 'playbook', yml.path])
    assert runmock.called


def test_ansible_without_args(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'ansible'])
    (out, err) = capsys.readouterr()
    assert 'Usage:' in out or 'usage:' in err
    assert '<host-pattern> [options]' in out or 'pattern' in err


def test_ansible_with_nonexisting_instance(capsys, ctrl, mock):
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'ansible', 'bar'])
    (out, err) = capsys.readouterr()
    assert "No hosts matched" in err


def test_ansible(ctrl, mock, monkeypatch):
    runmock = mock.MagicMock()
    if ANSIBLE1:
        monkeypatch.setattr("ansible.runner.Runner.run", runmock)
        runmock.return_value = dict(
            contacted=dict(),
            dark=[])
    else:
        monkeypatch.setattr("ansible.cli.adhoc.AdHocCLI.run", runmock)
        runmock.return_value = 0
    ctrl(['./bin/ploy', 'ansible', 'default-foo', '-a', 'ls'])
    assert runmock.called


class PasswordDeleteError(Exception):
    pass


class MockKeyringErrors:
    PasswordDeleteError = PasswordDeleteError


class MockKeyring:
    errors = MockKeyringErrors()

    def __init__(self):
        self.passwords = {}

    def delete_password(self, system, username):
        if system == "ploy_ansible":
            if username in self.passwords:
                del self.passwords[username]
                return
        raise PasswordDeleteError()

    def get_password(self, system, username):
        if system == "ploy_ansible":
            return self.passwords.get(username)

    def set_password(self, system, username, password):
        if system == "ploy_ansible":
            self.passwords[username] = password


@pytest.fixture
def getpass(mock, monkeypatch):
    getpass = mock.MagicMock()
    monkeypatch.setattr("getpass.getpass", getpass)
    return getpass


@pytest.fixture
def keyring(monkeypatch):
    keyring = MockKeyring()
    monkeypatch.setattr("ploy_ansible.KeyringSource.keyring", keyring)
    return keyring


def test_vault_key_generate(ctrl, keyring, ployconf):
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    assert 'ploy_ansible-test-key' not in keyring.passwords
    ctrl(['./bin/ploy', 'vault-key', 'generate'])
    assert 'ploy_ansible-test-key' in keyring.passwords


def test_vault_key_set(ctrl, getpass, keyring, ployconf):
    getpass.return_value = "foo"
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    assert 'ploy_ansible-test-key' not in keyring.passwords
    ctrl(['./bin/ploy', 'vault-key', 'set'])
    assert keyring.passwords['ploy_ansible-test-key'] == "foo"


def test_vault_key_set_existing(ctrl, getpass, keyring, mock, ployconf):
    getpass.return_value = "foo"
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    keyring.passwords['ploy_ansible-test-key'] = "bar"
    with mock.patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        ctrl(['./bin/ploy', 'vault-key', 'set'])
    assert keyring.passwords['ploy_ansible-test-key'] == "bar"
    with mock.patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = True
        ctrl(['./bin/ploy', 'vault-key', 'set'])
    assert keyring.passwords['ploy_ansible-test-key'] == "foo"


def test_vault_key_delete(ctrl, keyring, mock, ployconf):
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    keyring.passwords['ploy_ansible-test-key'] = "foo"
    with mock.patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        ctrl(['./bin/ploy', 'vault-key', 'delete'])
    assert 'ploy_ansible-test-key' in keyring.passwords
    with mock.patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = True
        ctrl(['./bin/ploy', 'vault-key', 'delete'])
    assert 'ploy_ansible-test-key' not in keyring.passwords
