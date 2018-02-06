from __future__ import unicode_literals


def test_inventory_yml_vars(ctrl, monkeypatch, ployconf, tempdir):
    from ploy_ansible.inventory import InventoryManager
    monkeypatch.setattr(InventoryManager, '_ploy_ctrl', ctrl)
    ployconf.fill([
        '[dummy-instance:foo]',
        'test = 1',
        'host = foo'])
    tempdir['group_vars/all.yml'].fill([
        '---',
        'ham: egg'])
    tempdir['host_vars/default-foo.yml'].fill([
        '---',
        'blubber: bla'])
    variables = ctrl.instances['foo'].get_ansible_variables()
    assert set(variables).intersection(('blubber', 'ham', 'ploy_test')) == set(
        ('blubber', 'ham', 'ploy_test'))
    assert variables['blubber'] == 'bla'
    assert variables['ham'] == 'egg'
    assert variables['ploy_test'] == '1'


def test_inventory_groups(ctrl, monkeypatch, ployconf, tempdir):
    from ploy_ansible.inventory import InventoryManager
    monkeypatch.setattr(InventoryManager, '_ploy_ctrl', ctrl)
    ployconf.fill([
        '[dummy-instance:foo]',
        'test = 1',
        'host = foo',
        'groups = foo bar'])
    tempdir['group_vars/foo.yml'].fill([
        '---',
        'ham: egg'])
    tempdir['group_vars/bar.yml'].fill([
        '---',
        'blubber: bla'])
    variables = ctrl.instances['foo'].get_ansible_variables()
    assert set(variables).intersection(('blubber', 'ham', 'ploy_test')) == set(
        ('blubber', 'ham', 'ploy_test'))
    assert variables['blubber'] == 'bla'
    assert variables['ham'] == 'egg'
    assert variables['ploy_test'] == '1'
