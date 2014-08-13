from ploy.tests.conftest import ployconf, tempdir  # noqa
import logging
import pytest


(ployconf,)  # shutup pyflakes


@pytest.fixture
def caplog(caplog):
    def messages(self, level=logging.INFO):
        return [
            x.message
            for x in self.records()
            if x.levelno >= level]
    caplog.messages = messages.__get__(caplog, caplog.__class__)
    return caplog


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
