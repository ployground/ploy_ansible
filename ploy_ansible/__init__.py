import argparse
import logging
import pkg_resources
import os
import sys
from ploy.common import yesno
from os.path import pathsep


log = logging.getLogger('ploy_ansible')


def inject_ansible_paths():
    # collect and inject ansible paths (roles and library) from entrypoints
    try:
        import ansible.constants as C
    except ImportError:
        log.error("Can't import ansible, check whether it's installed correctly.")
        sys.exit(1)
    extra_roles = []
    extra_library = []
    for entrypoint in pkg_resources.iter_entry_points(group='ansible_paths'):
        pathinfo = entrypoint.load()
        extra_roles.extend(pathinfo.get('roles', []))
        extra_library.extend(pathinfo.get('library', []))
    C.DEFAULT_ROLES_PATH = pathsep.join([pathsep.join(extra_roles), C.DEFAULT_ROLES_PATH])
    C.DEFAULT_MODULE_PATH = pathsep.join([pathsep.join(extra_library), C.DEFAULT_MODULE_PATH])


def get_playbooks_directory(main_config):
    ansible_config = main_config.get('global', {}).get('ansible', {})
    default = os.path.dirname(main_config.path)
    return ansible_config.get('playbooks-directory', default)


class AnsibleCmd(object):
    """Run Ansible"""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        inject_ansible_paths()
        import ansible.constants as C
        from ansible.runner import Runner
        from ansible import errors
        from ansible import callbacks
        from ploy_ansible.inventory import Inventory
        from ansible import utils
        parser = utils.base_parser(
            constants=C,
            runas_opts=True,
            subset_opts=True,
            output_opts=True,
            check_opts=True,
            diff_opts=False,
            usage='%s ansible <host-pattern> [options]' % self.ctrl.progname
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

        # su and sudo command line arguments need to be mutually exclusive
        if (hasattr(options, 'su')
                and (options.su or options.su_user or options.ask_su_pass)
                and (options.sudo or options.sudo_user or options.ask_sudo_pass)):
            parser.error("Sudo arguments ('--sudo', '--sudo-user', and '--ask-sudo-pass') "
                         "and su arguments ('-su', '--su-user', and '--ask-su-pass') are "
                         "mutually exclusive")

        if hasattr(options, 'ask_vault_pass') and (options.ask_vault_pass and options.vault_password_file):
                parser.error("--ask-vault-pass and --vault-password-file are mutually exclusive")

        cbs = callbacks.CliRunnerCallbacks()
        cbs.options = options
        pattern = args[0]
        patch_connect(self.ctrl)
        inventory_manager = Inventory(self.ctrl)
        if options.subset:
            inventory_manager.subset(options.subset)
        sudopass = None
        su_pass = None
        vault_pass = None
        kw = {}
        options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
        kw['ask_sudo_pass'] = options.ask_sudo_pass
        if hasattr(options, 'ask_su_pass'):
            options.ask_su_pass = options.ask_su_pass or C.DEFAULT_ASK_SU_PASS
            kw['ask_su_pass'] = options.ask_sudo_pass
        if hasattr(options, 'ask_vault_pass'):
            options.ask_vault_pass = options.ask_vault_pass or C.DEFAULT_ASK_VAULT_PASS
            kw['ask_vault_pass'] = options.ask_vault_pass
        passwds = utils.ask_passwords(**kw)
        if len(passwds) == 2:
            (sshpass, sudopass) = passwds
        elif len(passwds) == 3:
            (sshpass, sudopass, su_pass) = passwds
        else:
            (sshpass, sudopass, su_pass, vault_pass) = passwds
        if getattr(options, 'vault_password_file', None):
            this_path = os.path.expanduser(options.vault_password_file)
            try:
                f = open(this_path, "rb")
                tmp_vault_pass = f.read().strip()
                f.close()
            except (OSError, IOError), e:
                raise errors.AnsibleError("Could not read %s: %s" % (this_path, e))

            if not options.ask_vault_pass:
                vault_pass = tmp_vault_pass

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

        if options.sudo_user or options.ask_sudo_pass:
            options.sudo = True
        options.sudo_user = options.sudo_user or C.DEFAULT_SUDO_USER
        if hasattr(options, 'su'):
            if options.su_user or options.ask_su_pass:
                options.su = True
            options.su_user = options.su_user or C.DEFAULT_SU_USER
        if options.tree:
            utils.prepare_writeable_dir(options.tree)
        kw = {}
        if hasattr(options, 'su'):
            kw['su'] = options.su
            kw['su_user'] = options.su_user
        if hasattr(options, 'su_pass'):
            kw['su_pass'] = options.su_pass
        if vault_pass:
            kw['vault_password'] = vault_pass
        runner = Runner(
            module_name=options.module_name,
            module_path=options.module_path,
            module_args=options.module_args,
            remote_user=options.remote_user,
            inventory=inventory_manager,
            timeout=options.timeout,
            private_key_file=options.private_key_file,
            forks=options.forks,
            pattern=pattern,
            callbacks=cbs,
            sudo=options.sudo,
            sudo_pass=sudopass,
            sudo_user=options.sudo_user,
            transport='ssh',
            subset=options.subset,
            check=options.check,
            diff=options.check,
            **kw)
        results = runner.run()
        for result in results['contacted'].values():
            if 'failed' in result or result.get('rc', 0) != 0:
                sys.exit(2)
        if results['dark']:
            sys.exit(3)


class AnsiblePlaybookCmd(object):
    """Run Ansible playbook"""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        inject_ansible_paths()
        import ansible.playbook
        import ansible.constants as C
        from ansible import __version__
        from ansible import errors
        from ansible import callbacks
        from ploy_ansible.inventory import Inventory
        from ansible import utils
        from ansible.color import ANSIBLE_COLOR, stringc

        ansible_version = tuple(int(x) for x in __version__.split('.'))
        parser = utils.base_parser(
            constants=C,
            connect_opts=True,
            runas_opts=True,
            subset_opts=True,
            check_opts=True,
            diff_opts=True,
            usage='%s playbook playbook.yml' % self.ctrl.progname
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
        if ansible_version >= (1, 6):
            parser.add_option(
                '--force-handlers', dest='force_handlers', action='store_true',
                help="run handlers even if a task fails")
        options, args = parser.parse_args(argv)
        cbs = callbacks.CliRunnerCallbacks()
        cbs.options = options
        if len(args) == 0:
            parser.print_help(file=sys.stderr)
            sys.exit(1)

        # su and sudo command line arguments need to be mutually exclusive
        if (hasattr(options, 'su')
                and (options.su or options.su_user or options.ask_su_pass)
                and (options.sudo or options.sudo_user or options.ask_sudo_pass)):
            parser.error("Sudo arguments ('--sudo', '--sudo-user', and '--ask-sudo-pass') "
                         "and su arguments ('-su', '--su-user', and '--ask-su-pass') are "
                         "mutually exclusive")

        if hasattr(options, 'ask_vault_pass') and (options.ask_vault_pass and options.vault_password_file):
                parser.error("--ask-vault-pass and --vault-password-file are mutually exclusive")

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
            patch_connect(self.ctrl)
            inventory = Inventory(self.ctrl)
            sudopass = None
            su_pass = None
            vault_pass = None
            if not options.listhosts and not options.syntax and not options.listtasks:
                kw = {}
                options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
                kw['ask_sudo_pass'] = options.ask_sudo_pass
                if hasattr(options, 'ask_su_pass'):
                    options.ask_su_pass = options.ask_su_pass or C.DEFAULT_ASK_SU_PASS
                    kw['ask_su_pass'] = options.ask_sudo_pass
                if hasattr(options, 'ask_vault_pass'):
                    options.ask_vault_pass = options.ask_vault_pass or C.DEFAULT_ASK_VAULT_PASS
                    kw['ask_vault_pass'] = options.ask_vault_pass
                passwds = utils.ask_passwords(**kw)
                if len(passwds) == 2:
                    (sshpass, sudopass) = passwds
                elif len(passwds) == 3:
                    (sshpass, sudopass, su_pass) = passwds
                else:
                    (sshpass, sudopass, su_pass, vault_pass) = passwds
                if options.sudo_user or options.ask_sudo_pass:
                    options.sudo = True
                options.sudo_user = options.sudo_user or C.DEFAULT_SUDO_USER
                if hasattr(options, 'su'):
                    if options.su_user or options.ask_su_pass:
                        options.su = True
                    options.su_user = options.su_user or C.DEFAULT_SU_USER
                if getattr(options, 'vault_password_file', None):
                    this_path = os.path.expanduser(options.vault_password_file)
                    try:
                        f = open(this_path, "rb")
                        tmp_vault_pass = f.read().strip()
                        f.close()
                    except (OSError, IOError), e:
                        raise errors.AnsibleError("Could not read %s: %s" % (this_path, e))

                    if not options.ask_vault_pass:
                        vault_pass = tmp_vault_pass
            extra_vars = {}
            for extra_vars_opt in options.extra_vars:
                if extra_vars_opt.startswith("@"):
                    # Argument is a YAML file (JSON is a subset of YAML)
                    kw = {}
                    if vault_pass:
                        kw['vault_password'] = vault_pass
                    extra_vars = utils.combine_vars(extra_vars, utils.parse_yaml_from_file(extra_vars_opt[1:]), **kw)
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
                playbook = os.path.abspath(playbook)

                # let inventory know which playbooks are using so it can know the basedirs
                inventory.set_playbook_basedir(os.path.dirname(playbook))

                stats = callbacks.AggregateStats()
                playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
                if options.step:
                    playbook_cb.step = options.step
                if options.start_at:
                    playbook_cb.start_at = options.start_at
                runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

                kw = {}
                if hasattr(options, 'su'):
                    kw['su'] = options.su
                    kw['su_user'] = options.su_user
                if hasattr(options, 'su_pass'):
                    kw['su_pass'] = options.su_pass
                if vault_pass:
                    kw['vault_password'] = vault_pass
                if hasattr(options, 'force_handlers'):
                    kw['force_handlers'] = options.force_handlers
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
                    diff=options.diff,
                    **kw)

                if options.listhosts or options.listtasks or options.syntax:
                    print ''
                    print 'playbook: %s' % playbook
                    print ''
                    playnum = 0
                    for (play_ds, play_basedir) in zip(pb.playbook, pb.play_basedirs):
                        playnum += 1
                        play = ansible.playbook.Play(pb, play_ds, play_basedir)
                        label = play.name
                        hosts = pb.inventory.list_hosts(play.hosts)
                        # Filter all tasks by given tags
                        if pb.only_tags != 'all':
                            if options.subset and not hosts:
                                continue
                            matched_tags, unmatched_tags = play.compare_tags(pb.only_tags)

                            # Remove skipped tasks
                            matched_tags = matched_tags - set(pb.skip_tags)

                            unmatched_tags.discard('all')
                            unknown_tags = ((set(pb.only_tags) | set(pb.skip_tags)) -
                                            (matched_tags | unmatched_tags))

                            if unknown_tags:
                                continue

                        if options.listhosts:
                            print '  play #%d (%s): host count=%d' % (playnum, label, len(hosts))
                            for host in hosts:
                                print '    %s' % host

                        if options.listtasks:
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
        except errors.AnsibleError as e:
            callbacks.display("ERROR: %s" % e, color='red', stderr=True)
            sys.exit(1)


class AnsibleConfigureCmd(object):

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_completion(self):
        instances = set()
        for instance in self.ctrl.instances:
            if self.ctrl.instances[instance].has_playbook():
                instances.add(instance)
        return sorted(instances)

    def __call__(self, argv, help):
        """Configure an instance (ansible playbook run) after it has been started."""
        parser = argparse.ArgumentParser(
            prog="%s configure" % self.ctrl.progname,
            description=help,
            add_help=False,
        )
        parser.add_argument(
            '-v', '--verbose', default=False, action="count",
            help="verbose mode (-vvv for more, -vvvv to enable connection debugging)")
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
        instance = self.ctrl.instances[args.instance[0]]
        only_tags = args.only_tags.split(",")
        skip_tags = args.skip_tags
        if skip_tags is not None:
            skip_tags = skip_tags.split(",")
        instance.hooks.before_ansible_configure(instance)
        instance.configure(
            only_tags=only_tags,
            skip_tags=skip_tags,
            verbosity=args.verbose)
        instance.hooks.after_ansible_configure(instance)


def connect_patch_factory(ctrl):
    def connect_patch(self, host, port, user, password, transport, private_key_file):
        self.runner._ploy_ctrl = ctrl
        return self._ploy_orig_connect(host, port, user, password, transport, private_key_file)
    return connect_patch


def patch_connect(ctrl):
    import pkg_resources
    from ansible.utils import plugins
    path = os.path.dirname(
        pkg_resources.resource_filename(
            'ploy_ansible',
            'execnet_connection.py'))
    plugins.connection_loader.add_directory(path)
    try:
        from ansible.runner.connection import Connector
    except ImportError:
        from ansible.runner.connection import Connection as Connector
    if not hasattr(Connector, '_ploy_orig_connect'):
        Connector._ploy_orig_connect = Connector.connect
        Connector.connect = connect_patch_factory(ctrl)


def has_playbook(self):
    playbooks_directory = get_playbooks_directory(self.master.main_config)
    playbook_path = os.path.join(playbooks_directory, '%s.yml' % self.uid)
    if os.path.exists(playbook_path):
        return True
    if 'playbook' in self.config:
        return True
    if 'roles' in self.config:
        return True
    return False


def get_playbook(self, *args, **kwargs):
    inject_ansible_paths()
    import ansible.playbook
    import ansible.callbacks
    import ansible.errors
    import ansible.utils
    from ploy_ansible.inventory import Inventory

    host = self.uid
    user = self.config.get('user', 'root')
    playbooks_directory = get_playbooks_directory(self.master.main_config)

    class PlayBook(ansible.playbook.PlayBook):
        def __init__(self, *args, **kwargs):
            self.roles = kwargs.pop('roles', None)
            if self.roles is not None:
                if isinstance(self.roles, basestring):
                    self.roles = self.roles.split()
                kwargs['playbook'] = '<dynamically generated from %s>' % self.roles
            ansible.playbook.PlayBook.__init__(self, *args, **kwargs)
            self.basedir = playbooks_directory

        def _load_playbook_from_file(self, *args, **kwargs):
            if self.roles is None:
                return ansible.playbook.PlayBook._load_playbook_from_file(
                    self, *args, **kwargs)
            return (
                [{
                    'hosts': [host],
                    'user': user,
                    'roles': self.roles}],
                [playbooks_directory])

    patch_connect(self.master.ctrl)
    playbook = kwargs.pop('playbook', None)
    if playbook is None:
        playbook_path = os.path.join(playbooks_directory, '%s.yml' % self.uid)
        if os.path.exists(playbook_path):
            playbook = playbook_path
        if 'playbook' in self.config:
            if playbook is not None and playbook != self.config['playbook']:
                log.warning("Instance '%s' has the 'playbook' option set, but there is also a playbook at the default location '%s', which differs from '%s'." % (self.config_id, playbook, self.config['playbook']))
            playbook = self.config['playbook']
    if playbook is not None:
        log.info("Using playbook at '%s'." % playbook)
    roles = kwargs.pop('roles', None)
    if roles is None and 'roles' in self.config:
        roles = self.config['roles']
    if roles is not None and playbook is not None:
        log.error("You can't use a playbook and the 'roles' options at the same time for instance '%s'." % self.config_id)
        sys.exit(1)
    stats = ansible.callbacks.AggregateStats()
    callbacks = ansible.callbacks.PlaybookCallbacks(verbose=ansible.utils.VERBOSITY)
    runner_callbacks = ansible.callbacks.PlaybookRunnerCallbacks(stats, verbose=ansible.utils.VERBOSITY)
    inventory = Inventory(self.master.ctrl)
    skip_host_check = kwargs.pop('skip_host_check', False)
    if roles is None:
        kwargs['playbook'] = playbook
    else:
        kwargs['roles'] = roles
    try:
        pb = PlayBook(
            *args,
            callbacks=callbacks,
            inventory=inventory,
            runner_callbacks=runner_callbacks,
            stats=stats,
            **kwargs)
    except ansible.errors.AnsibleError as e:
        log.error("AnsibleError: %s" % e)
        sys.exit(1)
    for (play_ds, play_basedir) in zip(pb.playbook, pb.play_basedirs):
        if 'user' not in play_ds:
            play_ds['user'] = self.config.get('user', 'root')
        if not skip_host_check:
            hosts = play_ds.get('hosts', '')
            if isinstance(hosts, basestring):
                hosts = hosts.split(':')
            if self.uid not in hosts:
                log.warning("The host '%s' is not in the list of hosts (%s) of '%s'.", self.uid, ','.join(hosts), playbook)
                if not yesno("Do you really want to apply '%s' to the host '%s'?" % (playbook, self.uid)):
                    sys.exit(1)
        play_ds['hosts'] = [self.uid]
    return pb


def apply_playbook(self, playbook, *args, **kwargs):
    self.get_playbook(playbook=playbook, *args, **kwargs).run()


def configure(self, *args, **kwargs):
    verbosity = kwargs.pop('verbosity', 0)
    pb = self.get_playbook(*args, **kwargs)
    # we have to wait importing ansible until after get_playbook ran, so the import order is correct
    import ansible.errors
    import ansible.utils
    VERBOSITY = ansible.utils.VERBOSITY
    ansible.utils.VERBOSITY = verbosity
    try:
        pb.run()
    except ansible.errors.AnsibleError as e:
        log.error("AnsibleError: %s" % e)
        sys.exit(1)
    finally:
        ansible.utils.VERBOSITY = VERBOSITY


def get_ansible_variables(self):
    from ploy_ansible.inventory import Inventory
    inventory = Inventory(self.master.ctrl)
    return inventory.get_variables(self.uid)


def augment_instance(instance):
    if not hasattr(instance, 'apply_playbook'):
        instance.apply_playbook = apply_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'has_playbook'):
        instance.has_playbook = has_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_playbook'):
        instance.get_playbook = get_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'configure'):
        instance.configure = configure.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_ansible_variables'):
        instance.get_ansible_variables = get_ansible_variables.__get__(instance, instance.__class__)


def get_commands(ctrl):
    return [
        ('ansible', AnsibleCmd(ctrl)),
        ('playbook', AnsiblePlaybookCmd(ctrl)),
        ('configure', AnsibleConfigureCmd(ctrl))]


def get_massagers():
    from ploy.config import PathMassager
    return [
        PathMassager('ansible', 'playbooks-directory'),
        PathMassager('global', 'playbooks-directory')]


plugin = dict(
    augment_instance=augment_instance,
    get_commands=get_commands,
    get_massagers=get_massagers)
