import argparse
import getpass
import logging
import pkg_resources
import os
import subprocess
import sys
from binascii import b2a_base64
from lazy import lazy
from ploy.common import yesno
from operator import attrgetter
from os.path import pathsep


log = logging.getLogger('ploy_ansible')


ansible_paths = dict(
    lookup=[os.path.join(os.path.abspath(os.path.dirname(__file__)), 'lookup_plugins')])


def get_ansible_version():
    from ansible import __version__
    return tuple(int(x) for x in __version__.split('.'))


def inject_ansible_paths():
    # collect and inject ansible paths (roles and library) from entrypoints
    try:
        import ansible.constants as C
        import ansible
    except ImportError:
        log.error("Can't import ansible, check whether it's installed correctly.")
        sys.exit(1)
    if get_ansible_version() >= (1, 10):
        log.warn(
            "You are using an untested version %s of ansible. "
            "The latest tested version is 1.9.X. "
            "Any errors may be caused by that newer version." % ansible.__version__)
    extra_roles = []
    extra_library = []
    plugin_path_names = set(x for x in dir(C) if x.endswith('_PLUGIN_PATH'))
    extra_plugins = {}
    for entrypoint in pkg_resources.iter_entry_points(group='ansible_paths'):
        pathinfo = entrypoint.load()
        extra_roles.extend(pathinfo.get('roles', []))
        extra_library.extend(pathinfo.get('library', []))
        for key in pathinfo:
            plugin_path_name = 'DEFAULT_%s_PLUGIN_PATH' % key.upper()
            if plugin_path_name in plugin_path_names:
                extra_plugins.setdefault(plugin_path_name, []).extend(pathinfo[key])
    roles = list(extra_roles)
    if C.DEFAULT_ROLES_PATH is not None:
        roles.append(C.DEFAULT_ROLES_PATH)
    if roles:
        C.DEFAULT_ROLES_PATH = pathsep.join(roles)
    library = list(extra_library)
    if C.DEFAULT_MODULE_PATH is not None:
        library.append(C.DEFAULT_MODULE_PATH)
    if library:
        C.DEFAULT_MODULE_PATH = pathsep.join(library)
    for attr in extra_plugins:
        setattr(C, attr, pathsep.join([pathsep.join(extra_plugins[attr]), getattr(C, attr)]))


def get_playbooks_directory(main_config):
    ansible_config = main_config.get('global', {}).get('ansible', {})
    default = os.path.dirname(main_config.path)
    return ansible_config.get('playbooks-directory', default)


class NullSource:
    def get(self, fail_on_error=True):
        return

    def set(self, key):
        log.error("No vault password source set.")
        sys.exit(1)

    def delete(self):
        log.error("No vault password source set.")
        sys.exit(1)


class KeyringSource:
    keyring = None

    def __init__(self, id):
        if self.keyring is None:
            try:
                import keyring
            except ImportError:
                log.error("Couldn't import 'keyring' library.")
                sys.exit(1)
            self.keyring = keyring
        if not id:
            log.error("No unique id for vault password in keyring secified.")
            sys.exit(1)
        self.id = id

    def get(self, fail_on_error=True):
        result = self.keyring.get_password("ploy_ansible", self.id)
        if result is None and fail_on_error:
            log.error("No password stored in keyring for service 'ploy_ansible' with username '%s'." % self.id)
            log.info("Use the 'vault-key' command to manage your keys.")
            sys.exit(1)
        return result

    def set(self, key):
        if not key:
            log.error("You can't use an empty key.")
            sys.exit(1)
        self.keyring.set_password("ploy_ansible", self.id, key)

    def delete(self):
        try:
            self.keyring.delete_password("ploy_ansible", self.id)
        except self.keyring.errors.PasswordDeleteError as e:
            log.error("PasswordDeleteError: %s" % e)
            sys.exit(1)
        log.info("Key deleted from keyring for service 'ploy_ansible' with username '%s'." % self.id)


def get_vault_password_source(main_config, option='vault-password-source'):
    ansible_config = main_config.get('global', {}).get('ansible', {})
    src = ansible_config.get(option)
    if src is None:
        return NullSource()
    return KeyringSource(src)


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
        try:
            from ansible.utils.vault import VaultLib
        except ImportError:
            VaultLib = None
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

        if hasattr(options, 'become_ask_pass'):
            # privlege escalation command line arguments need to be mutually exclusive
            utils.check_mutually_exclusive_privilege(options, parser)
        else:
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
        vault_pass = None
        kw = {}
        if hasattr(options, 'become_ask_pass'):
            becomepass = None
            become_method = None
            utils.normalize_become_options(options)
            become_method = utils.choose_pass_prompt(options)
            kw['become_ask_pass'] = options.become_ask_pass
            kw['become_method'] = become_method
        else:
            sudopass = None
            su_pass = None
            options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
            kw['ask_sudo_pass'] = options.ask_sudo_pass
            if hasattr(options, 'ask_su_pass'):
                options.ask_su_pass = options.ask_su_pass or C.DEFAULT_ASK_SU_PASS
                kw['ask_su_pass'] = options.ask_sudo_pass
        if hasattr(options, 'ask_vault_pass'):
            options.ask_vault_pass = options.ask_vault_pass or C.DEFAULT_ASK_VAULT_PASS
            kw['ask_vault_pass'] = options.ask_vault_pass
        passwds = utils.ask_passwords(**kw)
        if hasattr(options, 'become_ask_pass'):
            (sshpass, becomepass, vault_pass) = passwds
        else:
            if len(passwds) == 2:
                (sshpass, sudopass) = passwds
            elif len(passwds) == 3:
                (sshpass, sudopass, su_pass) = passwds
            else:
                (sshpass, sudopass, su_pass, vault_pass) = passwds
        if VaultLib is not None and vault_pass is None:
            vault_pass = get_vault_password_source(self.ctrl.config).get()
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

        inventory_manager = Inventory(self.ctrl, vault_password=vault_pass)
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
        if options.module_name in ['command', 'shell'] and not options.module_args:
            callbacks.display("No argument passed to %s module" % options.module_name, color='red', stderr=True)
            sys.exit(1)

        if not hasattr(options, 'become_ask_pass'):
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
        if hasattr(options, 'become_ask_pass'):
            kw['become'] = options.become
            kw['become_method'] = options.become_method
            kw['become_pass'] = becomepass
            kw['become_user'] = options.become_user
        else:
            if hasattr(options, 'su'):
                kw['su'] = options.su
                kw['su_user'] = options.su_user
            if hasattr(options, 'su_pass'):
                kw['su_pass'] = options.su_pass
            kw['sudo'] = options.sudo
            kw['sudo_user'] = options.sudo_user
            kw['sudo_pass'] = sudopass
        if vault_pass:
            kw['vault_pass'] = vault_pass
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


def parse_extra_vars(extras, vault_pass=None):
    inject_ansible_paths()
    from ansible import utils
    extra_vars = {}
    for extra_vars_opt in extras:
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
    return extra_vars


class AnsiblePlaybookCmd(object):
    """Run Ansible playbook"""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        inject_ansible_paths()
        import ansible.playbook
        import ansible.constants as C
        from ansible import errors
        from ansible import callbacks
        from ploy_ansible.inventory import Inventory
        from ansible import utils
        from ansible.color import ANSIBLE_COLOR, stringc
        try:
            from ansible.utils.vault import VaultLib
        except ImportError:
            VaultLib = None

        ansible_version = get_ansible_version()
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
        if not parser.has_option('--extra-vars'):
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

        if hasattr(options, 'become_ask_pass'):
            # privlege escalation command line arguments need to be mutually exclusive
            utils.check_mutually_exclusive_privilege(options, parser)
        else:
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
            if hasattr(options, 'become_ask_pass'):
                becomepass = None
            else:
                sudopass = None
                su_pass = None
            vault_pass = None
            if not options.listhosts and not options.syntax and not options.listtasks:
                kw = {}
                if hasattr(options, 'become_ask_pass'):
                    utils.normalize_become_options(options)
                    become_method = utils.choose_pass_prompt(options)
                    kw['become_ask_pass'] = options.become_ask_pass
                    kw['become_method'] = become_method
                else:
                    options.ask_sudo_pass = options.ask_sudo_pass or C.DEFAULT_ASK_SUDO_PASS
                    kw['ask_sudo_pass'] = options.ask_sudo_pass
                    if hasattr(options, 'ask_su_pass'):
                        options.ask_su_pass = options.ask_su_pass or C.DEFAULT_ASK_SU_PASS
                        kw['ask_su_pass'] = options.ask_sudo_pass
                if hasattr(options, 'ask_vault_pass'):
                    options.ask_vault_pass = options.ask_vault_pass or C.DEFAULT_ASK_VAULT_PASS
                    kw['ask_vault_pass'] = options.ask_vault_pass
                passwds = utils.ask_passwords(**kw)
                if hasattr(options, 'become_ask_pass'):
                    (sshpass, becomepass, vault_pass) = passwds
                else:
                    if len(passwds) == 2:
                        (sshpass, sudopass) = passwds
                    elif len(passwds) == 3:
                        (sshpass, sudopass, su_pass) = passwds
                    else:
                        (sshpass, sudopass, su_pass, vault_pass) = passwds
                if VaultLib is not None and vault_pass is None:
                    vault_pass = get_vault_password_source(self.ctrl.config).get()
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
            inventory = Inventory(self.ctrl, vault_password=vault_pass)
            extra_vars = parse_extra_vars(options.extra_vars, vault_pass=vault_pass)
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
                if hasattr(options, 'become_ask_pass'):
                    kw['become'] = options.become
                    kw['become_method'] = options.become_method
                    kw['become_pass'] = becomepass
                    kw['become_user'] = options.become_user
                else:
                    if hasattr(options, 'su'):
                        kw['su'] = options.su
                        kw['su_user'] = options.su_user
                    if hasattr(options, 'su_pass'):
                        kw['su_pass'] = options.su_pass
                    kw['sudo'] = options.sudo
                    kw['sudo_user'] = options.sudo_user
                    kw['sudo_pass'] = sudopass
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
    """Configure an instance (ansible playbook run) after it has been started."""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_completion(self):
        instances = set()
        for instance in self.ctrl.instances:
            if self.ctrl.instances[instance].has_playbook():
                instances.add(instance)
        return sorted(instances)

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="%s configure" % self.ctrl.progname,
            description=help)
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
            '-e', '--extra-vars',
            dest="extra_vars",
            action="append",
            default=[],
            help="set additional variables as key=value or YAML/JSON")
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
        extra_vars = parse_extra_vars(args.extra_vars)
        instance.hooks.before_ansible_configure(instance)
        instance.configure(
            only_tags=only_tags,
            skip_tags=skip_tags,
            extra_vars=extra_vars,
            verbosity=args.verbose)
        instance.hooks.after_ansible_configure(instance)


class AnsibleInventoryCmd(object):
    """Print the inventory of all instances."""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="%s inventory" % self.ctrl.progname,
            description=help)
        parser.parse_args(argv)
        inventory = _get_ansible_inventory(self.ctrl, self.ctrl.config)
        groups = sorted(inventory.groups, key=attrgetter('name'))
        for group in groups:
            print group.name
            hosts = sorted(group.hosts, key=attrgetter('name'))
            for host in hosts:
                print "    %s" % host.name
            print


class AnsibleVaultKeyCmd(object):
    """Manage vault keys."""

    # Additional GPG parameters. Used for testing.
    gpg_opts = ()

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_completion(self):
        return ('delete', 'export', 'generate', 'import', 'set')

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="%s vault-key" % self.ctrl.progname,
            description=help)
        subparsers = parser.add_subparsers(help="sub commands of vault-key command")
        parser.add_argument(
            '-o', '--old',
            action="store_true",
            help="use 'vault-password-old-source'")
        deleteparser = subparsers.add_parser(
            "delete",
            help="delete the vault key")
        deleteparser.set_defaults(func=self.cmd_delete)
        exportparser = subparsers.add_parser(
            "export",
            help="export key from gpg encrypted file")
        exportparser.add_argument("recipient")
        exportparser.add_argument("file", nargs='?')
        exportparser.set_defaults(func=self.cmd_export)
        generateparser = subparsers.add_parser(
            "generate",
            help="generate a new random 32 byte vault key and store it")
        generateparser.set_defaults(func=self.cmd_generate)
        importparser = subparsers.add_parser(
            "import",
            help="import key from gpg encrypted file")
        importparser.add_argument("file")
        importparser.set_defaults(func=self.cmd_import)
        setparser = subparsers.add_parser(
            "set",
            help="set the vault key")
        setparser.set_defaults(func=self.cmd_set)
        args = parser.parse_args(argv)
        if args.old:
            src = get_vault_password_source(self.ctrl.config, option='vault-password-old-source')
        else:
            src = get_vault_password_source(self.ctrl.config)
        args.func(args, src)

    def cmd_export(self, args, src):
        key = src.get()
        recipient = args.recipient
        if args.file:
            fn = args.file
        else:
            fn = os.path.join(self.ctrl.config.path, "%s.key.gpg" % recipient)
        cmd = ['gpg', '--quiet', '--no-tty', '--armor', '--batch', '--encrypt']
        cmd.extend(self.gpg_opts)
        cmd.extend(['--recipient', recipient, '--output', fn])
        gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        gpg.communicate(key)
        if gpg.returncode != 0:
            log.error('GPG returned non-zero exit code.')
            log.info('Command used: %s', ' '.join(cmd))
            sys.exit(gpg.returncode)
        log.info("Encrypted key into '%s'." % fn)

    def cmd_generate(self, args, src):
        if src.get(fail_on_error=False) and not yesno("There is already a key stored, do you want to replace it?"):
            sys.exit(1)
        key = b2a_base64(os.urandom(32))
        key = key.strip()
        key = key.replace('+', '-')
        key = key.replace('/', '_')
        src.set(key)

    def cmd_import(self, args, src):
        if src.get(fail_on_error=False) and not yesno("There is already a key stored, do you want to replace it?"):
            return
        cmd = ['gpg', '--quiet', '--no-tty', '--decrypt']
        cmd.extend(self.gpg_opts)
        cmd.extend([args.file])
        key = subprocess.check_output(cmd)
        src.set(key)

    def cmd_set(self, args, src):
        if src.get(fail_on_error=False) and not yesno("There is already a key stored, do you want to replace it?"):
            return
        src.set(getpass.getpass("Password for '%s': " % src.id))

    def cmd_delete(self, args, src):
        if yesno("Do you really want to delete the key for '%s'?" % src.id):
            src.delete()


class AnsibleVaultCmd(object):
    """Manage vault encrypted files."""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_completion(self):
        return ('create', 'decrypt', 'edit', 'encrypt', 'rekey')

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="%s vault" % self.ctrl.progname,
            description=help)
        subparsers = parser.add_subparsers(help="sub commands of vault command")
        catparser = subparsers.add_parser("cat", help="cat contents of an encrypted file")
        catparser.add_argument("file", nargs=1)
        catparser.set_defaults(func=self.cmd_cat)
        createparser = subparsers.add_parser("create", help="create an encrypted file")
        createparser.add_argument("file", nargs=1)
        createparser.set_defaults(func=self.cmd_create)
        decryptparser = subparsers.add_parser("decrypt", help="decrypt encrypted files")
        decryptparser.add_argument("file", nargs="+")
        decryptparser.set_defaults(func=self.cmd_decrypt)
        editparser = subparsers.add_parser("edit", help="edit an encrypted file")
        editparser.add_argument("file", nargs=1)
        editparser.set_defaults(func=self.cmd_edit)
        encryptparser = subparsers.add_parser("encrypt", help="encrypt unencrypted files")
        encryptparser.add_argument("file", nargs="+")
        encryptparser.set_defaults(func=self.cmd_encrypt)
        rekeyparser = subparsers.add_parser("rekey", help="rekey encrypted files")
        rekeyparser.add_argument("file", nargs="+")
        rekeyparser.set_defaults(func=self.cmd_rekey)
        args = parser.parse_args(argv)
        args.func(args)

    @lazy
    def AnsibleError(self):
        inject_ansible_paths()
        from ansible.errors import AnsibleError
        return AnsibleError

    @lazy
    def ve(self):
        inject_ansible_paths()
        try:
            from ansible.utils.vault import VaultEditor
        except ImportError:
            log.error("Your ansible installation doesn't support vaults.")
            sys.exit(1)
        return VaultEditor

    @lazy
    def vl(self):
        inject_ansible_paths()
        try:
            from ansible.utils.vault import VaultLib
        except ImportError:
            log.error("Your ansible installation doesn't support vaults.")
            sys.exit(1)
        return VaultLib

    def cmd_cat(self, args):
        password = get_vault_password_source(self.ctrl.config).get()
        this_editor = self.ve(None, password, args.file[0])
        vl = self.vl(password)
        try:
            sys.stdout.write(vl.decrypt(this_editor.read_data(this_editor.filename)))
            sys.stdout.flush()
        except self.AnsibleError as e:
            log.error("%s" % e)
            sys.exit(1)

    def cmd_create(self, args):
        password = get_vault_password_source(self.ctrl.config).get()
        this_editor = self.ve(None, password, args.file[0])
        try:
            this_editor.create_file()
        except self.AnsibleError as e:
            log.error("%s" % e)

    def cmd_decrypt(self, args):
        password = get_vault_password_source(self.ctrl.config).get()
        for f in args.file:
            this_editor = self.ve(None, password, f)
            try:
                this_editor.decrypt_file()
            except self.AnsibleError as e:
                log.error("%s" % e)
            log.info("Decrypted %s" % f)

    def cmd_edit(self, args):
        password = get_vault_password_source(self.ctrl.config).get()
        this_editor = self.ve(None, password, args.file[0])
        try:
            this_editor.edit_file()
        except self.AnsibleError as e:
            log.error("%s" % e)

    def cmd_encrypt(self, args):
        password = get_vault_password_source(self.ctrl.config).get()
        for f in args.file:
            this_editor = self.ve(None, password, f)
            try:
                this_editor.encrypt_file()
            except self.AnsibleError as e:
                log.error("%s" % e)
            log.info("Encrypted %s" % f)

    def cmd_rekey(self, args):
        old_password = get_vault_password_source(self.ctrl.config, option='vault-password-old-source').get()
        if old_password is None:
            log.error("You have to specify the old vault password source with the 'vault-password-old-source' option.")
            sys.exit(1)
        password = get_vault_password_source(self.ctrl.config).get()
        for f in args.file:
            this_editor = self.ve(None, old_password, f)
            try:
                this_editor.rekey_file(password)
            except self.AnsibleError as e:
                log.error("%s" % e)
            log.info("Rekeyed %s" % f)


def connect_patch_factory(ctrl):
    def connect_patch(self, *args, **kwargs):
        self.runner._ploy_ctrl = ctrl
        return self._ploy_orig_connect(*args, **kwargs)
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
    try:
        from ansible.utils.vault import VaultLib
    except ImportError:
        VaultLib = None
    from ploy_ansible.inventory import Inventory

    host = self.uid
    user = self.config.get('user', 'root')
    sudo = self.config.get('sudo')
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
            settings = {
                'hosts': [host],
                'user': user,
                'roles': self.roles}
            if sudo is not None:
                settings['sudo'] = sudo
            return (
                [settings],
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
    skip_host_check = kwargs.pop('skip_host_check', False)
    if roles is None:
        kwargs['playbook'] = playbook
    else:
        kwargs['roles'] = roles
    if VaultLib is not None:
        kwargs['vault_password'] = get_vault_password_source(self.master.main_config).get()
    inventory = Inventory(self.master.ctrl, vault_password=kwargs.get('vault_password'))
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


class AnsibleVariablesDict(dict):
    def __getitem__(self, name):
        from ansible.utils.template import template
        return template(self.basedir, dict.__getitem__(self, name), self, fail_on_undefined=True)


def _get_ansible_inventory(ctrl, main_config):
    inject_ansible_paths()
    from ploy_ansible.inventory import Inventory
    vault_password = get_vault_password_source(main_config).get(fail_on_error=False)
    return Inventory(ctrl, vault_password=vault_password)


def get_ansible_inventory(self):
    return _get_ansible_inventory(self.master.ctrl, self.master.main_config)


def get_ansible_variables(self):
    inventory = self.get_ansible_inventory()
    basedir = get_playbooks_directory(self.master.ctrl.config)
    result = AnsibleVariablesDict(inventory.get_variables(self.uid))
    result.basedir = basedir
    return result


def get_vault_lib(self):
    try:
        from ansible.utils.vault import VaultLib
    except ImportError:
        return None
    return VaultLib(get_vault_password_source(self.master.main_config).get())


def augment_instance(instance):
    if not hasattr(instance, 'apply_playbook'):
        instance.apply_playbook = apply_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'has_playbook'):
        instance.has_playbook = has_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_playbook'):
        instance.get_playbook = get_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'configure'):
        instance.configure = configure.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_ansible_inventory'):
        instance.get_ansible_inventory = get_ansible_inventory.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_ansible_variables'):
        instance.get_ansible_variables = get_ansible_variables.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_vault_lib'):
        instance.get_vault_lib = get_vault_lib.__get__(instance, instance.__class__)


def get_commands(ctrl):
    return [
        ('ansible', AnsibleCmd(ctrl)),
        ('playbook', AnsiblePlaybookCmd(ctrl)),
        ('configure', AnsibleConfigureCmd(ctrl)),
        ('inventory', AnsibleInventoryCmd(ctrl)),
        ('vault', AnsibleVaultCmd(ctrl)),
        ('vault-key', AnsibleVaultKeyCmd(ctrl))]


def get_massagers():
    from ploy.config import PathMassager
    return [
        PathMassager('ansible', 'playbooks-directory'),
        PathMassager('global', 'playbooks-directory')]


plugin = dict(
    augment_instance=augment_instance,
    get_commands=get_commands,
    get_massagers=get_massagers)
