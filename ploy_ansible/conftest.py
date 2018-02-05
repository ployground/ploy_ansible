import logging
import pytest


@pytest.fixture
def caplog(caplog):
    def messages(self, level=logging.INFO):
        return [
            x.message
            for x in self.records
            if x.levelno >= level]
    caplog.messages = messages.__get__(caplog, caplog.__class__)
    return caplog


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
    return ctrl
