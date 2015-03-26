from mock import MagicMock, patch
import pytest


def test_register_ansible_module_path():
    pass


def test_register_ansible_module_path_from_multiple_entry_points():
    pass


def test_configure_without_args(ctrl):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: ploy configure' in output
    assert 'too few arguments' in output


def test_configure_with_nonexisting_instance(ctrl):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'bar'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: ploy configure' in output
    assert "argument instance: invalid choice: 'bar'" in output


def test_configure_with_missing_yml(ctrl):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'foo'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'usage: ploy configure' in output
    assert "argument instance: invalid choice: 'foo'" in output


def test_configure_with_empty_yml(ctrl, tempdir):
    tempdir['default-foo.yml'].fill('')
    with patch('ploy_ansible.log') as LogMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'foo'])
    assert len(LogMock.error.call_args_list) == 1
    call_args = LogMock.error.call_args_list[0][0]
    assert 'parse error: playbooks must be formatted as a YAML list' in call_args[0]


def test_configure_asks_when_no_host_in_yml(ctrl, tempdir):
    yml = tempdir['default-foo.yml']
    yml.fill([
        '---',
        '- {}'])
    with patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'configure', 'foo'])
    assert len(YesNoMock.call_args_list) == 1
    call_args = YesNoMock.call_args_list[0][0]
    assert "Do you really want to apply '%s' to the host '%s'?" % (yml.path, 'default-foo') in call_args[0]


def test_configure(ctrl, monkeypatch, tempdir):
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    runmock = MagicMock()
    monkeypatch.setattr("ansible.playbook.PlayBook.run", runmock)
    ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called


def test_configure_playbook_option(ctrl, ployconf, tempdir):
    import ansible.playbook
    yml = tempdir['default-bar.yml']
    yml.fill([
        '---',
        '- hosts: default-foo'])
    ployconf.fill([
        '[dummy-instance:foo]',
        'playbook = %s' % yml.path])
    with patch.object(ansible.playbook.PlayBook, "run", autospec=True) as runmock:
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called
    assert runmock.call_args[0][0].filename == yml.path


def test_configure_playbook_option_shadowing(ctrl, ployconf, caplog, tempdir):
    import ansible.playbook
    yml_foo = tempdir['default-foo.yml']
    yml_foo.fill('')
    yml_bar = tempdir['default-bar.yml']
    yml_bar.fill([
        '---',
        '- hosts: default-foo'])
    ployconf.fill([
        '[dummy-instance:foo]',
        'playbook = %s' % yml_bar.path])
    with patch.object(ansible.playbook.PlayBook, "run", autospec=True) as runmock:
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called
    assert runmock.call_args[0][0].filename == yml_bar.path
    assert [x.message for x in caplog.records()] == [
        "Instance 'dummy-instance:foo' has the 'playbook' option set, but there is also a playbook at the default location '%s', which differs from '%s'." % (yml_foo.path, yml_bar.path),
        "Using playbook at '%s'." % yml_bar.path]


def test_configure_roles_option(ctrl, ployconf, tempdir):
    import ansible.playbook
    ployconf.fill([
        '[dummy-instance:foo]',
        'roles = ham egg'])
    with patch.object(ansible.playbook.PlayBook, "run", autospec=True) as runmock:
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert runmock.called
    assert runmock.call_args[0][0].filename == "<dynamically generated from ['ham', 'egg']>"
    assert runmock.call_args[0][0].playbook == [{'hosts': ['default-foo'], 'user': 'root', 'roles': ['ham', 'egg']}]
    assert runmock.call_args[0][0].play_basedirs == [tempdir.directory]


def test_configure_roles_default_playbook_conflict(ctrl, ployconf, caplog, tempdir):
    yml = tempdir['default-foo.yml']
    yml.fill('')
    ployconf.fill([
        '[dummy-instance:foo]',
        'roles = ham egg'])
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert [x.message for x in caplog.records()] == [
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
        'roles = ham egg'])
    with pytest.raises(SystemExit):
        ctrl(['./bin/ploy', 'configure', 'foo'])
    assert [x.message for x in caplog.records()] == [
        "Using playbook at '%s'." % yml.path,
        "You can't use a playbook and the 'roles' options at the same time for instance 'dummy-instance:foo'."]


def test_configure_with_extra_vars(ctrl, monkeypatch, tempdir):
    import ansible.playbook
    tempdir['default-foo.yml'].fill([
        '---',
        '- hosts: default-foo'])
    with patch.object(ansible.playbook.PlayBook, "run", autospec=True) as runmock:
        ctrl(['./bin/ploy', 'configure', 'foo', '-e', 'foo=bar', '-e', 'bar=foo'])
    assert runmock.called
    assert runmock.call_args[0][0].extra_vars == dict(foo='bar', bar='foo')


def test_playbook_without_args(ctrl):
    with patch('sys.stderr') as StdErrMock:
        StdErrMock.encoding = 'utf-8'
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'playbook'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'Usage: ploy playbook playbook.yml' in output


def test_playbook_with_nonexisting_playbook(ctrl):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'playbook', 'bar.yml'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert "the playbook: bar.yml could not be found" in output


def test_playbook_with_empty_yml(ctrl, tempdir):
    yml = tempdir['foo.yml']
    yml.fill('')
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'playbook', yml.path])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'parse error: playbooks must be formatted as a YAML list' in output


def test_playbook_asks_when_no_host_in_yml(ctrl, tempdir):
    yml = tempdir['foo.yml']
    yml.fill([
        '---',
        '- {}'])
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'playbook', yml.path])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert 'hosts declaration is required' in output


def test_playbook(ctrl, monkeypatch, tempdir):
    yml = tempdir['foo.yml']
    yml.fill([
        '---',
        '- hosts: foo'])
    runmock = MagicMock()
    monkeypatch.setattr("ansible.playbook.PlayBook.run", runmock)
    ctrl(['./bin/ploy', 'playbook', yml.path])
    assert runmock.called


def test_ansible_without_args(ctrl):
    with patch('sys.stdout') as StdOutMock:
        StdOutMock.encoding = 'utf-8'
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'ansible'])
    output = "".join(x[0][0] for x in StdOutMock.write.call_args_list)
    assert 'Usage: ploy ansible' in output


def test_ansible_with_nonexisting_instance(ctrl):
    with patch('sys.stderr') as StdErrMock:
        with pytest.raises(SystemExit):
            ctrl(['./bin/ploy', 'ansible', 'bar'])
    output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    assert "No hosts matched" in output


def test_ansible(ctrl, monkeypatch):
    runmock = MagicMock()
    monkeypatch.setattr("ansible.runner.Runner.run", runmock)
    runmock.return_value = dict(
        contacted=dict(),
        dark=[])
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
def getpass(monkeypatch):
    getpass = MagicMock()
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


def test_vault_key_set_existing(ctrl, getpass, keyring, ployconf):
    getpass.return_value = "foo"
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    keyring.passwords['ploy_ansible-test-key'] = "bar"
    with patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        ctrl(['./bin/ploy', 'vault-key', 'set'])
    assert keyring.passwords['ploy_ansible-test-key'] == "bar"
    with patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = True
        ctrl(['./bin/ploy', 'vault-key', 'set'])
    assert keyring.passwords['ploy_ansible-test-key'] == "foo"


def test_vault_key_delete(ctrl, keyring, ployconf):
    ployconf.fill([
        '[ansible]',
        'vault-password-source = ploy_ansible-test-key'])
    keyring.passwords['ploy_ansible-test-key'] = "foo"
    with patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = False
        ctrl(['./bin/ploy', 'vault-key', 'delete'])
    assert 'ploy_ansible-test-key' in keyring.passwords
    with patch('ploy_ansible.yesno') as YesNoMock:
        YesNoMock.return_value = True
        ctrl(['./bin/ploy', 'vault-key', 'delete'])
    assert 'ploy_ansible-test-key' not in keyring.passwords
