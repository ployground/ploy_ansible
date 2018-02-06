from ansible.inventory.host import Host as BaseHost
from ansible.inventory.manager import InventoryData
from ansible.inventory.manager import InventoryManager as BaseInventoryManager
import logging


log = logging.getLogger('ploy_ansible.inventory')


class HostAddress(unicode):
    pass


class Host(BaseHost):
    def __init__(self, ctrl, name):
        BaseHost.__init__(self, name)
        self.ctrl = ctrl
        instance = self.ctrl.instances[self.name]
        self.address = HostAddress(instance.get_host())
        self.address.instance = instance

    @property
    def vars(self):
        instance = self.ctrl.instances[self.name]
        results = dict(
            self._ploy_vars,
            # ansible_connection='execnet_connection',
            ansible_ssh_port=int(instance.get_port()),
            ansible_ssh_user=instance.config.get('user', 'root'),
            _ploy_instance=instance,
            _ploy_instances=self.ctrl.instances)
        for k, v in instance.config.items():
            if k == 'password' and instance.config['password-fallback']:
                results['ansible_ssh_pass'] = v
            elif k.startswith('ansible_'):
                results[k] = v
            elif k.startswith('ansible-'):
                results[k[len('ansible-'):].replace('-', '_')] = v
            else:
                results['ploy_%s' % k.replace('-', '_')] = v
        return results

    @vars.setter
    def vars(self, value):
        self._ploy_vars = value


class InventoryManager(BaseInventoryManager):
    def __init__(self, loader=None, sources=None):
        self._inventory = InventoryData()
        self._restriction = None
        self._subset = None
        self._hosts_patterns_cache = {}
        self._pattern_cache = {}
        self._sources = []

        for instance in self._ploy_ctrl.instances.values():
            if instance.uid in self._inventory.hosts:
                continue
            h = Host(self._ploy_ctrl, instance.uid)
            self._inventory.hosts[instance.uid] = h
            add_to = ['all', '%ss' % instance.sectiongroupname]
            if hasattr(instance, 'master'):
                master = instance.master
                if instance == getattr(master, 'instance', None):
                    add_to.append('masters')
                else:
                    add_to.append('%s-instances' % master.id)
            add_to.extend(instance.config.get('groups', '').split())
            for group in add_to:
                self.add_group(group)
                self.add_host(instance.uid, group)
