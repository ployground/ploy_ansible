import argparse
import logging
import os
import sys


log = logging.getLogger('mr.awsome.ansible')


class Ansible(object):
    """Apply an Ansible playbook on the server"""

    def __init__(self, aws):
        self.aws = aws

    def get_completion(self):
        return list(self.get_instances())

    def get_instances(self):
        instances = {}
        for name, instance in self.aws.get_instances(command='init_ssh_key').items():
            if 'playbooks' in instance.config:
                instances[name] = instance
        return instances

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="aws pb",
            description=help,
        )
        instances = self.get_instances()
        parser.add_argument("server", nargs=1,
                            metavar="instance",
                            help="Name of the instance from the config.",
                            choices=list(instances))
        parser.add_argument('-l', '--list',
                            action='store_true',
                            help="List configured playbooks")
        pb_action = parser.add_argument("playbook", nargs="?",
                            help="Name of the playbook from the config.")
        args = parser.parse_args(argv)
        server = instances[args.server[0]]
        playbooks = server.config['playbooks']
        pb_action.choices = list(playbooks)
        args = parser.parse_args(argv)
        if args.list:
            print "Available playbooks:"
            print
            for pb in server.config['playbooks']:
                print "   ", pb
            return
        server.apply_playbook(self.aws, playbooks[args.playbook])


class Inventory(object):
    def __init__(self, instance):
        self.instance = instance

    def get_variables(self, hostname):
        result = dict(
            ansible_connection='ssh')
        if 'user' in self.instance.config:
            result['ansible_ssh_user'] = self.instance.config['user']
        if 'user' in self.instance.config:
            result['ansible_ssh_user'] = self.instance.config['user']
        if 'ansible_python_interpreter' in self.instance.config:
            result['ansible_python_interpreter'] = self.instance.config['ansible_python_interpreter']
        return result

    def basedir(self):
        return

    def src(self):
        return

    def list_hosts(self, pattern):
        return [pattern]

    def also_restrict_to(self, restriction):
        print 'also_restrict_to', repr(restriction)

    def lift_also_restriction(self):
        pass

    def restrict_to(self, restriction):
        print 'restrict_to', repr(restriction)

    def lift_restriction(self):
        pass

    def groups_list(self):
        return []


def connect_patch_factory(aws):
    def connect_patch(self, host, port, user, password, transport, private_key_file):
        assert transport == 'ssh'
        instance = aws.instances[host]
        try:
            ssh_info = instance.init_ssh_key(user=user)
        except instance.paramiko.SSHException, e:
            log.error("Couldn't validate fingerprint for ssh connection.")
            log.error(unicode(e))
            log.error("Is the server finished starting up?")
            sys.exit(1)
        client = ssh_info['client']
        client.get_transport().sock.close()
        client.close()
        result = self._awsome_orig_connect(
            ssh_info['host'],
            int(ssh_info['port']),
            ssh_info['user'],
            password,
            transport,
            private_key_file)
        result.delegate = host
        for key in ssh_info:
            if key[0].isupper():
                result.common_args.append('-o')
                result.common_args.append('%s=%s' % (key, ssh_info[key]))
        return result
    return connect_patch


def apply_playbook(self, aws, playbook, *args, **kwargs):
    import ansible.playbook
    import ansible.callbacks
    import ansible.errors
    import ansible.utils
    from ansible.runner.connection import Connection
    if not hasattr(Connection, '_awsome_orig_connect'):
        Connection._awsome_orig_connect = Connection.connect
        Connection.connect = connect_patch_factory(aws)
    stats=ansible.callbacks.AggregateStats()
    callbacks=ansible.callbacks.PlaybookCallbacks(verbose=ansible.utils.VERBOSITY)
    runner_callbacks=ansible.callbacks.PlaybookRunnerCallbacks(stats, verbose=ansible.utils.VERBOSITY)
    try:
        pb = ansible.playbook.PlayBook(
            playbook=playbook,
            callbacks=callbacks,
            inventory=Inventory(self),
            runner_callbacks=runner_callbacks,
            stats=stats)
    except ansible.errors.AnsibleError as e:
        log.error(e)
        sys.exit(1)
    for (play_ds, play_basedir) in zip(pb.playbook, pb.play_basedirs):
        play_ds['hosts'] = [self.id]
        play = ansible.playbook.Play(pb, play_ds, play_basedir)
        print 'play:', play.name
        for task in play.tasks():
            if getattr(task, 'name', None) is not None:
                print '    task:', task.name
    pb.run()


def augment_instance(instance):
    if not hasattr(instance, 'apply_playbook'):
        instance.apply_playbook = apply_playbook.__get__(instance, instance.__class__)


def get_commands(aws):
    return [('pb', Ansible(aws))]


class PlaybooksMassager(object):
    sectiongroupname = None
    key = 'playbooks'

    def __call__(self, main_config, sectiongroupname, sectionname):
        value = main_config[sectiongroupname][sectionname][self.key]
        result = {}
        for path in value.split():
            if not path:
                continue
            parts = path.split('=', 1)
            if len(parts) > 1:
                name = parts[0]
                path = parts[1]
            else:
                path = parts[0]
                name = os.path.splitext(os.path.basename(path))[0]
            path = os.path.expanduser(path)
            if not os.path.isabs(path):
                path = os.path.join(main_config.path, path)
            result[name] = path
        return result



def get_massagers():
    return [PlaybooksMassager()]


plugin = dict(
    augment_instance=augment_instance,
    get_commands=get_commands,
    get_massagers=get_massagers)
