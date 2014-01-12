from ansible.inventory import Group
from ansible.inventory import Host
from ansible.inventory import Inventory as BaseInventory


class Inventory(BaseInventory):
    def __init__(self, aws):
        BaseInventory.__init__(
            self,
            host_list=[])
        self.aws = aws
        groups = {}
        groups['all'] = self.get_group('all')
        for instance in self.aws.instances.values():
            h = Host(instance.id)
            add_to = ['all', '%ss' % instance.sectiongroupname]
            if hasattr(instance, 'master'):
                if instance == instance.master.instance:
                    add_to.append('masters')
                else:
                    add_to.append('%s-instances' % instance.master.id)
            for group in add_to:
                g = groups.get(group)
                if g is None:
                    g = self.get_group(group)
                    if g is None:
                        g = Group(group)
                        self.add_group(g)
                    groups[group] = g
                g.add_host(h)

    def _get_variables(self, hostname):
        result = dict(
            ansible_connection='ssh')
        instance = self.aws.instances[hostname]
        for k, v in instance.config.items():
            if k == 'user':
                result['ansible_ssh_user'] = v
            elif k == 'password' and instance.config['password-fallback']:
                result['ansible_ssh_pass'] = v
                result['ansible_connection'] = 'paramiko'
            elif k.startswith('ansible_'):
                result[k] = v
            elif k.startswith('ansible-'):
                result[k[len('ansible-'):]] = v
        return result
