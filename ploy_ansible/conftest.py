import pytest


@pytest.fixture
def ctrl(ployconf):
    from ploy import Controller
    import ploy_ansible
    import ploy.tests.dummy_plugin
    ployconf.fill([
        '[dummy-instance:foo]',
        'host = foo'])
    ctrl = Controller(ployconf.directory)
    ctrl.configfile = ployconf.path
    ctrl.plugins = {
        'dummy': ploy.tests.dummy_plugin.plugin,
        'ansible': ploy_ansible.plugin}
    if hasattr(ploy_ansible, 'display'):
        ploy_ansible.display._deprecations.clear()
        ploy_ansible.display._warns.clear()
        ploy_ansible.display._errors.clear()
    ploy_ansible.inject_ansible_paths(ctrl=ctrl)
    yield ctrl
    if ploy_ansible.ANSIBLE_HAS_CONTEXT:
        from ansible import context
        context.CLIARGS = context.CLIArgs({})
