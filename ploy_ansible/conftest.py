from ploy.tests.conftest import ployconf, tempdir  # noqa
import pytest


(ployconf,)  # shutup pyflakes


@pytest.fixture
def ctrl(ployconf):
    from ploy import Controller
    import ploy_ansible
    import ploy.tests.dummy_plugin
    ployconf.fill([
        '[dummy-instance:foo]'])
    ctrl = Controller(configpath=ployconf.directory)
    ctrl.plugins = {
        'dummy': ploy.tests.dummy_plugin.plugin,
        'ansible': ploy_ansible.plugin}
    return ctrl
