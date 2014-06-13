from ansible import errors
from ansible.inventory import Group
from ansible.inventory import Host
from ansible.inventory import Inventory as BaseInventory
from ansible.inventory.vars_plugins.group_vars import VarsModule


class Inventory(BaseInventory):
    def __init__(self, aws):
        from mr.awsome_ansible import get_playbooks_directory
        BaseInventory.__init__(
            self,
            host_list=[])
        self.aws = aws
        self.set_playbook_basedir(get_playbooks_directory(aws.config))
        groups = {}
        groups['all'] = self.get_group('all')
        for instance in self.aws.instances.values():
            h = Host(instance.id)
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
        self._vars_plugins = []
        self._vars_plugins.append(VarsModule(self))

    def _get_variables(self, hostname, **kwargs):
        host = self.get_host(hostname)
        if host is None:
            raise errors.AnsibleError("host not found: %s" % hostname)
        result = dict(ansible_connection='execnet_connection')
        instance = self.aws.instances[hostname]
        for k, v in instance.config.items():
            if k == 'password' and instance.config['password-fallback']:
                result['ansible_ssh_pass'] = v
            elif k.startswith('ansible_'):
                result[k] = v
            elif k.startswith('ansible-'):
                result[k[len('ansible-'):].replace('-', '_')] = v
            else:
                result['awsome_%s' % k.replace('-', '_')] = v
        vars = {}
        for plugin in self.aws.plugins.values():
            if 'get_ansible_vars' not in plugin:
                continue
            vars.update(plugin['get_ansible_vars'](instance))
        vars_results = [plugin.run(host) for plugin in self._vars_plugins]
        for updated in vars_results:
            if updated is not None:
                vars.update(updated)
        vars.update(result)
        return vars
