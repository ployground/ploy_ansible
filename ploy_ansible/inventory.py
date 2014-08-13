from ansible import errors
from ansible import utils
from ansible.inventory import Group
from ansible.inventory import Host
from ansible.inventory import Inventory as BaseInventory
import inspect
import logging


log = logging.getLogger('ploy_ansible.inventory')


class PloyInventoryDict(dict):
    def __getitem__(self, name):
        if name.startswith('awsome_'):
            caller_frame = inspect.currentframe().f_back
            info = inspect.getframeinfo(caller_frame)
            new_name = "ploy_%s" % name[7:]
            log.warning("Use of deprecated variable name '%s', use '%s' instead.\n%s:%s\n%s" % (
                name, new_name, info.filename, info.lineno, ''.join(info.code_context)))
        return dict.__getitem__(self, name)


class Inventory(BaseInventory):
    def __init__(self, ctrl):
        from ploy_ansible import get_playbooks_directory
        BaseInventory.__init__(
            self,
            host_list=[])
        self.ctrl = ctrl
        self.set_playbook_basedir(get_playbooks_directory(ctrl.config))
        groups = {}
        groups['all'] = self.get_group('all')
        seen = set()
        for instance in self.ctrl.instances.values():
            if instance.uid in seen:
                continue
            seen.add(instance.uid)
            h = Host(instance.uid)
            add_to = ['all', '%ss' % instance.sectiongroupname]
            if hasattr(instance, 'master'):
                master = instance.master
                if instance == getattr(master, 'instance', None):
                    add_to.append('masters')
                else:
                    add_to.append('%s-instances' % master.id)
            for group in add_to:
                g = groups.get(group)
                if g is None:
                    g = self.get_group(group)
                    if g is None:
                        g = Group(group)
                        self.add_group(g)
                    groups[group] = g
                g.add_host(h)
        self._vars_plugins = [x for x in utils.plugins.vars_loader.all(self)]

    def _get_variables(self, hostname, **kwargs):
        host = self.get_host(hostname)
        if host is None:
            raise errors.AnsibleError("host not found: %s" % hostname)
        result = dict(ansible_connection='execnet_connection')
        instance = self.ctrl.instances[hostname]
        for k, v in instance.config.items():
            if k == 'password' and instance.config['password-fallback']:
                result['ansible_ssh_pass'] = v
            elif k.startswith('ansible_'):
                result[k] = v
            elif k.startswith('ansible-'):
                result[k[len('ansible-'):].replace('-', '_')] = v
            else:
                result['ploy_%s' % k.replace('-', '_')] = v
                result['awsome_%s' % k.replace('-', '_')] = v
        vars = {}
        for plugin in self.ctrl.plugins.values():
            if 'get_ansible_vars' not in plugin:
                continue
            vars = utils.combine_vars(vars, plugin['get_ansible_vars'](instance))
        vars_results = [plugin.run(host) for plugin in self._vars_plugins if hasattr(plugin, 'run')]
        for updated in vars_results:
            if updated is not None:
                vars = utils.combine_vars(vars, updated)
        vars_results = [plugin.get_host_vars(host) for plugin in self._vars_plugins if hasattr(plugin, 'get_host_vars')]
        for updated in vars_results:
            if updated is not None:
                vars = utils.combine_vars(vars, updated)
        vars = utils.combine_vars(vars, host.get_variables())
        if self.parser is not None:
            vars = utils.combine_vars(vars, self.parser.get_host_variables(host))
        if hasattr(self, 'get_host_vars'):
            vars = utils.combine_vars(vars, self.get_host_vars(host))
        vars = utils.combine_vars(vars, result)
        return PloyInventoryDict(vars)
