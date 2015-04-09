from ploy_ansible.inventory import Inventory


def test_inventory_deprecation(caplog, ctrl, ployconf):
    ctrl.configfile = ployconf.path
    ployconf.fill([
        '[dummy-instance:foo]',
        'test = 1'])
    inventory = Inventory(ctrl)
    variables = inventory.get_variables('default-foo')
    assert caplog.messages() == []
    assert variables['ploy_test']
    assert caplog.messages() == []
    assert variables['awsome_test']
    msg, = caplog.messages()
    lines = msg.splitlines()
    assert lines[0] == "Use of deprecated variable name 'awsome_test', use 'ploy_test' instead."
    parts = lines[1].rsplit(':', 1)
    assert parts[0].endswith("ploy_ansible/test_inventory.py")
    assert lines[2] == "    assert variables['awsome_test']"


def test_inventory_yml_vars(ctrl, ployconf, tempdir):
    ctrl.configfile = ployconf.path
    ployconf.fill([
        '[dummy-instance:foo]',
        'test = 1'])
    tempdir['group_vars/all.yml'].fill([
        '---',
        'ham: egg'])
    tempdir['host_vars/default-foo.yml'].fill([
        '---',
        'blubber: bla'])
    inventory = Inventory(ctrl)
    variables = inventory.get_variables('default-foo')
    assert set(variables).intersection(('blubber', 'ham', 'ploy_test')) == set(
        ('blubber', 'ham', 'ploy_test'))
    assert variables['blubber'] == 'bla'
    assert variables['ham'] == 'egg'
    assert variables['ploy_test'] == '1'


def test_inventory_groups(ctrl, ployconf, tempdir):
    ctrl.configfile = ployconf.path
    ployconf.fill([
        '[dummy-instance:foo]',
        'test = 1',
        'groups = foo bar'])
    tempdir['group_vars/foo.yml'].fill([
        '---',
        'ham: egg'])
    tempdir['group_vars/bar.yml'].fill([
        '---',
        'blubber: bla'])
    inventory = Inventory(ctrl)
    variables = inventory.get_variables('default-foo')
    assert set(variables).intersection(('blubber', 'ham', 'ploy_test')) == set(
        ('blubber', 'ham', 'ploy_test'))
    assert variables['blubber'] == 'bla'
    assert variables['ham'] == 'egg'
    assert variables['ploy_test'] == '1'
