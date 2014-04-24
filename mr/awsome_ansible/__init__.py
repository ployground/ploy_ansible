import argparse
import logging
import pkg_resources
import os
import sys
from mr.awsome.common import yesno
from os.path import pathsep


log = logging.getLogger('mr.awsome.ansible')


def inject_ansible_paths():
    # collect and inject ansible paths (roles and library) from entrypoints
    import ansible.constants as C
    extra_roles = []
    extra_library = []
    for entrypoint in pkg_resources.iter_entry_points(group='ansible_paths'):
        pathinfo = entrypoint.load()
        extra_roles.extend(pathinfo.get('roles', []))
        extra_library.extend(pathinfo.get('library', []))
    C.DEFAULT_ROLES_PATH = pathsep.join([pathsep.join(extra_roles), C.DEFAULT_ROLES_PATH])
    C.DEFAULT_MODULE_PATH = pathsep.join([pathsep.join(extra_library), C.DEFAULT_MODULE_PATH])


class AnsibleCmd(object):
    """Run Ansible"""

    def __init__(self, aws):
        self.aws = aws

    def __call__(self, argv, help):
        import ansible.constants as C
        from ansible.runner import Runner
        from ansible import callbacks
        from mr.awsome_ansible.inventory import Inventory
        from ansible import utils
        parser = utils.base_parser(
            constants=C,
            runas_opts=True,
            subset_opts=True,
            output_opts=True,
            check_opts=True,
            diff_opts=False,
            usage='aws ansible <host-pattern> [options]'
        )
        parser.remove_option('-i')
        parser.remove_option('-k')
        parser.add_option(
            '-a', '--args', dest='module_args',
            help="module arguments", default=C.DEFAULT_MODULE_ARGS)
        parser.add_option(
            '-m', '--module-name', dest='module_name',
            help="module name to execute (default=%s)" % C.DEFAULT_MODULE_NAME,
            default=C.DEFAULT_MODULE_NAME)
        options, args = parser.parse_args(argv)
        if len(args) == 0 or len(args) > 1:
            parser.print_help()
            sys.exit(1)
        cbs = callbacks.CliRunnerCallbacks()
        cbs.options = options
        pattern = args[0]
        patch_connect(self.aws)
        inventory_manager = Inventory(self.aws)
        if options.subset:
            inventory_manager.subset(options.subset)
        hosts = inventory_manager.list_hosts(pattern)
        if len(hosts) == 0:
            callbacks.display("No hosts matched", stderr=True)
            sys.exit(1)
        if options.listhosts:
            for host in hosts:
                callbacks.display('    %s' % host)
            sys.exit(0)
        if ((options.module_name == 'command' or options.module_name == 'shell')
                and not options.module_args):
            callbacks.display("No argument passed to %s module" % options.module_name, color='red', stderr=True)
            sys.exit(1)
        sudopass = None
        options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
        sudopass = utils.ask_passwords(ask_sudo_pass=options.ask_sudo_pass)
        if options.sudo_user or options.ask_sudo_pass:
            options.sudo = True
        options.sudo_user = options.sudo_user or C.DEFAULT_SUDO_USER
        if options.tree:
            utils.prepare_writeable_dir(options.tree)
        runner = Runner(
            module_name=options.module_name, module_path=options.module_path,
            module_args=options.module_args,
            remote_user=options.remote_user,
            inventory=inventory_manager, timeout=options.timeout,
            private_key_file=options.private_key_file,
            forks=options.forks,
            pattern=pattern,
            callbacks=cbs, sudo=options.sudo,
            sudo_pass=sudopass, sudo_user=options.sudo_user,
            transport='ssh', subset=options.subset,
            check=options.check,
            diff=options.check)
        results = runner.run()
        for result in results['contacted'].values():
            if 'failed' in result or result.get('rc', 0) != 0:
                sys.exit(2)
        if results['dark']:
            sys.exit(3)


class AnsiblePlaybookCmd(object):
    """Run Ansible playbook"""

    def __init__(self, aws):
        self.aws = aws

    def __call__(self, argv, help):
        inject_ansible_paths()
        import ansible.playbook
        import ansible.constants as C
        from ansible import errors
        from ansible import callbacks
        from mr.awsome_ansible.inventory import Inventory
        from ansible import utils
        from ansible.color import ANSIBLE_COLOR, stringc

        parser = utils.base_parser(
            constants=C,
            connect_opts=True,
            runas_opts=True,
            subset_opts=True,
            check_opts=True,
            diff_opts=True,
            usage='aws playbook playbook.yml'
        )
        parser.remove_option('-i')
        parser.remove_option('-k')
        parser.add_option(
            '-e', '--extra-vars', dest="extra_vars", action="append",
            help="set additional variables as key=value or YAML/JSON", default=[])
        parser.add_option(
            '-t', '--tags', dest='tags', default='all',
            help="only run plays and tasks tagged with these values")
        parser.add_option(
            '--skip-tags', dest='skip_tags',
            help="only run plays and tasks whose tags do not match these values")
        parser.add_option(
            '--syntax-check', dest='syntax', action='store_true',
            help="perform a syntax check on the playbook, but do not execute it")
        parser.add_option(
            '--list-tasks', dest='listtasks', action='store_true',
            help="list all tasks that would be executed")
        parser.add_option(
            '--step', dest='step', action='store_true',
            help="one-step-at-a-time: confirm each task before running")
        parser.add_option(
            '--start-at-task', dest='start_at',
            help="start the playbook at the task matching this name")
        options, args = parser.parse_args(argv)
        cbs = callbacks.CliRunnerCallbacks()
        cbs.options = options
        if len(args) == 0:
            parser.print_help(file=sys.stderr)
            sys.exit(1)

        def colorize(lead, num, color):
            """ Print 'lead' = 'num' in 'color' """
            if num != 0 and ANSIBLE_COLOR and color is not None:
                return "%s%s%-15s" % (stringc(lead, color), stringc("=", color), stringc(str(num), color))
            else:
                return "%s=%-4s" % (lead, str(num))

        def hostcolor(host, stats, color=True):
            if ANSIBLE_COLOR and color:
                if stats['failures'] != 0 or stats['unreachable'] != 0:
                    return "%-37s" % stringc(host, 'red')
                elif stats['changed'] != 0:
                    return "%-37s" % stringc(host, 'yellow')
                else:
                    return "%-37s" % stringc(host, 'green')
            return "%-26s" % host

        try:
            patch_connect(self.aws)
            inventory = Inventory(self.aws)
            sudopass = None
            if not options.listhosts and not options.syntax and not options.listtasks:
                options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
                sudopass = utils.ask_passwords(ask_sudo_pass=options.ask_sudo_pass)
                if options.sudo_user or options.ask_sudo_pass:
                    options.sudo = True
                options.sudo_user = options.sudo_user or C.DEFAULT_SUDO_USER
            extra_vars = {}
            for extra_vars_opt in options.extra_vars:
                if extra_vars_opt.startswith("@"):
                    # Argument is a YAML file (JSON is a subset of YAML)
                    extra_vars = utils.combine_vars(extra_vars, utils.parse_yaml_from_file(extra_vars_opt[1:]))
                elif extra_vars_opt and extra_vars_opt[0] in '[{':
                    # Arguments as YAML
                    extra_vars = utils.combine_vars(extra_vars, utils.parse_yaml(extra_vars_opt))
                else:
                    # Arguments as Key-value
                    extra_vars = utils.combine_vars(extra_vars, utils.parse_kv(extra_vars_opt))

            only_tags = options.tags.split(",")
            skip_tags = options.skip_tags
            if options.skip_tags is not None:
                skip_tags = options.skip_tags.split(",")

            for playbook in args:
                if not os.path.exists(playbook):
                    raise errors.AnsibleError("the playbook: %s could not be found" % playbook)

            # run all playbooks specified on the command line
            for playbook in args:

                # let inventory know which playbooks are using so it can know the basedirs
                inventory.set_playbook_basedir(os.path.dirname(playbook))

                stats = callbacks.AggregateStats()
                playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
                if options.step:
                    playbook_cb.step = options.step
                if options.start_at:
                    playbook_cb.start_at = options.start_at
                runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

                pb = ansible.playbook.PlayBook(
                    playbook=playbook,
                    module_path=options.module_path,
                    inventory=inventory,
                    forks=options.forks,
                    remote_user=options.remote_user,
                    callbacks=playbook_cb,
                    runner_callbacks=runner_cb,
                    stats=stats,
                    timeout=options.timeout,
                    transport=options.connection,
                    sudo=options.sudo,
                    sudo_user=options.sudo_user,
                    sudo_pass=sudopass,
                    extra_vars=extra_vars,
                    private_key_file=options.private_key_file,
                    only_tags=only_tags,
                    skip_tags=skip_tags,
                    check=options.check,
                    diff=options.diff
                )

                if options.listhosts or options.listtasks or options.syntax:
                    print ''
                    print 'playbook: %s' % playbook
                    print ''
                    playnum = 0
                    for (play_ds, play_basedir) in zip(pb.playbook, pb.play_basedirs):
                        playnum += 1
                        play = ansible.playbook.Play(pb, play_ds, play_basedir)
                        label = play.name
                        if options.listhosts:
                            hosts = pb.inventory.list_hosts(play.hosts)
                            print '  play #%d (%s): host count=%d' % (playnum, label, len(hosts))
                            for host in hosts:
                                print '    %s' % host
                        if options.listtasks:
                            matched_tags, unmatched_tags = play.compare_tags(pb.only_tags)

                            # Remove skipped tasks
                            matched_tags = matched_tags - set(pb.skip_tags)

                            unmatched_tags.discard('all')
                            unknown_tags = ((set(pb.only_tags) | set(pb.skip_tags)) -
                                            (matched_tags | unmatched_tags))

                            if unknown_tags:
                                continue
                            print '  play #%d (%s):' % (playnum, label)

                            for task in play.tasks():
                                _only_tags = set(task.tags).intersection(pb.only_tags)
                                _skip_tags = set(task.tags).intersection(pb.skip_tags)
                                if (_only_tags and not _skip_tags):
                                    if getattr(task, 'name', None) is not None:
                                        # meta tasks have no names
                                        print '    %s' % task.name
                        print ''
                    continue

                if options.syntax:
                    # if we've not exited by now then we are fine.
                    print 'Playbook Syntax is fine'
                    sys.exit(0)

                failed_hosts = []
                unreachable_hosts = []
                pb.run()

                hosts = sorted(pb.stats.processed.keys())
                callbacks.display(callbacks.banner("PLAY RECAP"))
                playbook_cb.on_stats(pb.stats)

                for h in hosts:
                    t = pb.stats.summarize(h)
                    if t['failures'] > 0:
                        failed_hosts.append(h)
                    if t['unreachable'] > 0:
                        unreachable_hosts.append(h)

                retries = failed_hosts + unreachable_hosts

                if len(retries) > 0:
                    filename = pb.generate_retry_inventory(retries)
                    if filename:
                        callbacks.display("           to retry, use: --limit @%s\n" % filename)

                for h in hosts:
                    t = pb.stats.summarize(h)

                    callbacks.display("%s : %s %s %s %s" % (
                        hostcolor(h, t),
                        colorize('ok', t['ok'], 'green'),
                        colorize('changed', t['changed'], 'yellow'),
                        colorize('unreachable', t['unreachable'], 'red'),
                        colorize('failed', t['failures'], 'red')),
                        screen_only=True
                    )

                    callbacks.display("%s : %s %s %s %s" % (
                        hostcolor(h, t, False),
                        colorize('ok', t['ok'], None),
                        colorize('changed', t['changed'], None),
                        colorize('unreachable', t['unreachable'], None),
                        colorize('failed', t['failures'], None)),
                        log_only=True
                    )

                print ""
                if len(failed_hosts) > 0:
                    sys.exit(2)
                if len(unreachable_hosts) > 0:
                    sys.exit(3)
        except errors.AnsibleError, e:
            callbacks.display("ERROR: %s" % e, color='red', stderr=True)
            sys.exit(1)


class AnsibleConfigureCmd(object):

    def __init__(self, aws):
        self.aws = aws
        self.ansible_config = self.aws.config.get('global', {}).get('ansible', {})
        self.playbooks_directory = self.ansible_config.get(
            'playbooks-directory',
            self.aws.config.path)

    def get_completion(self):
        instances = []
        for instance in self.aws.instances:
            if os.path.exists(os.path.join(self.playbooks_directory, '%s.yml' % instance)):
                instances.append(instance)
        return instances

    def __call__(self, argv, help):
        """Configure an instance (ansible playbook run) after it has been started."""
        parser = argparse.ArgumentParser(
            prog="ploy configure",
            description=help,
            add_help=False,
        )
        parser.add_argument(
            '-t', '--tags',
            dest='only_tags',
            default='all',
            help="only run plays and tasks tagged with these values")
        parser.add_argument(
            '--skip-tags',
            dest='skip_tags',
            help="only run plays and tasks whose tags do not match these values")
        parser.add_argument(
            "instance",
            nargs=1,
            metavar="instance",
            help="Name of the instance from the config.",
            choices=self.get_completion())
        args = parser.parse_args(argv)
        instance = self.aws.instances[args.instance[0]]
        playbook_path = os.path.join(self.playbooks_directory, '%s.yml' % args.instance[0])
        only_tags = args.only_tags.split(",")
        skip_tags = args.skip_tags
        if skip_tags is not None:
            skip_tags = skip_tags.split(",")
        instance.apply_playbook(
            playbook_path,
            only_tags=only_tags,
            skip_tags=skip_tags)


def connect_patch_factory(aws):
    from ansible import errors
    from ansible import utils
    _sshinfo_cache = {}

    def connect_patch(self, host, port, user, password, transport, private_key_file):
        if transport == 'local':
            return self._awsome_orig_connect(host, port, user, password, transport, private_key_file)
        if transport not in ('paramiko', 'ssh'):
            raise errors.AnsibleError("Invalid transport '%s' for mr.awsome instance." % transport)
        cache_key = (host, port, user, password, transport, private_key_file)
        if cache_key not in _sshinfo_cache:
            instance = aws.instances[host]
            if hasattr(instance, '_status'):
                if instance._status() != 'running':
                    raise errors.AnsibleError("Instance '%s' unavailable." % instance.id)
            try:
                ssh_info = instance.init_ssh_key(user=user)
            except instance.paramiko.SSHException:
                raise errors.AnsibleError("Couldn't validate fingerprint for '%s'." % instance.id)
            if transport == 'ssh':
                _sshinfo_cache[cache_key] = ssh_info
        else:
            ssh_info = _sshinfo_cache[cache_key]
        client = ssh_info.get('client')
        if client is not None and client.get_transport() is None:
            client = None
            del ssh_info['client']
        if transport == 'ssh' and client is not None:
            client.get_transport().sock.close()
            client.close()
        conn = utils.plugins.connection_loader.get(
            transport,
            self.runner,
            ssh_info['host'],
            int(ssh_info['port']),
            user=ssh_info['user'],
            password=password,
            private_key_file=private_key_file)
        if conn is None:
            raise errors.AnsibleError("unsupported connection type: %s" % transport)
        if transport == 'paramiko':
            conn.ssh = client
            self.active = conn
        else:
            self.active = conn.connect()
            for key in ssh_info:
                if key[0].isupper():
                    self.active.common_args.append('-o')
                    self.active.common_args.append('%s=%s' % (key, ssh_info[key]))
        self.active.delegate = host
        return self.active

    return connect_patch


def patch_connect(aws):
    from ansible.runner.connection import Connection
    if not hasattr(Connection, '_awsome_orig_connect'):
        Connection._awsome_orig_connect = Connection.connect
        Connection.connect = connect_patch_factory(aws)


def get_playbook(self, playbook, *args, **kwargs):
    inject_ansible_paths()
    import ansible.playbook
    import ansible.callbacks
    import ansible.errors
    import ansible.utils
    from mr.awsome_ansible.inventory import Inventory

    patch_connect(self.master.aws)
    stats = ansible.callbacks.AggregateStats()
    callbacks = ansible.callbacks.PlaybookCallbacks(verbose=ansible.utils.VERBOSITY)
    runner_callbacks = ansible.callbacks.PlaybookRunnerCallbacks(stats, verbose=ansible.utils.VERBOSITY)
    inventory = Inventory(self.master.aws)
    skip_host_check = kwargs.pop('skip_host_check', False)
    try:
        pb = ansible.playbook.PlayBook(
            *args,
            playbook=playbook,
            callbacks=callbacks,
            inventory=inventory,
            runner_callbacks=runner_callbacks,
            stats=stats,
            **kwargs)
    except ansible.errors.AnsibleError as e:
        log.error(e)
        sys.exit(1)
    for (play_ds, play_basedir) in zip(pb.playbook, pb.play_basedirs):
        if not skip_host_check:
            hosts = play_ds.get('hosts')
            if isinstance(hosts, basestring):
                hosts = hosts.split(':')
            if self.id not in hosts:
                log.warning("The host '%s' is not in the list of hosts (%s) of '%s'.", self.id, ','.join(hosts), playbook)
                if not yesno("Do you really want to apply '%s' to the host '%s' anyway?"):
                    sys.exit(1)
        play_ds['hosts'] = [self.id]
    return pb


def apply_playbook(self, playbook, *args, **kwargs):
    self.get_playbook(playbook, *args, **kwargs).run()


def get_ansible_variables(self):
    from mr.awsome_ansible.inventory import Inventory
    inventory = Inventory(self.master.aws)
    return inventory.get_variables(self.id)


def augment_instance(instance):
    if not hasattr(instance, 'apply_playbook'):
        instance.apply_playbook = apply_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_playbook'):
        instance.get_playbook = get_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_ansible_variables'):
        instance.get_ansible_variables = get_ansible_variables.__get__(instance, instance.__class__)


def get_commands(aws):
    return [
        ('ansible', AnsibleCmd(aws)),
        ('playbook', AnsiblePlaybookCmd(aws)),
        ('configure', AnsibleConfigureCmd(aws))]


def get_massagers():
    from mr.awsome.config import PathMassager
    return [PathMassager('global', 'playbooks-directory')]


plugin = dict(
    augment_instance=augment_instance,
    get_commands=get_commands,
    get_massagers=get_massagers)
