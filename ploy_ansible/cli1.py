from __future__ import print_function
import os
import sys


def connect_patch_factory(ctrl):
    def connect_patch(self, *args, **kwargs):
        self.runner._ploy_ctrl = ctrl
        return self._ploy_orig_connect(*args, **kwargs)
    return connect_patch


def patch_connect(ctrl):
    from ansible.runner.connection import Connector
    if not hasattr(Connector, '_ploy_orig_connect'):
        Connector._ploy_orig_connect = Connector.connect
        Connector.connect = connect_patch_factory(ctrl)


def parse_extra_vars(extras, vault_pass=None):
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


def get_vault_password_source(main_config, option='vault-password-source'):
    from ploy_ansible import KeyringSource, NullSource
    ansible_config = main_config.get('global', {}).get('ansible', {})
    src = ansible_config.get(option)
    if src is None:
        return NullSource()
    return KeyringSource(src)


def ansible_cmd(ctrl, argv):
    import ansible.constants as C
    from ansible.runner import Runner
    from ansible import errors
    from ansible import callbacks
    from ploy_ansible.inventory1 import Inventory
    from ansible import utils
    from ansible.utils.vault import VaultLib

    parser = utils.base_parser(
        constants=C,
        runas_opts=True,
        subset_opts=True,
        output_opts=True,
        check_opts=True,
        diff_opts=False,
        usage='%s ansible <host-pattern> [options]' % ctrl.progname
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
    patch_connect(ctrl)
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
        vault_pass = get_vault_password_source(ctrl.config).get()
    if getattr(options, 'vault_password_file', None):
        this_path = os.path.expanduser(options.vault_password_file)
        try:
            f = open(this_path, "rb")
            tmp_vault_pass = f.read().strip()
            f.close()
        except (OSError, IOError) as e:
            raise errors.AnsibleError("Could not read %s: %s" % (this_path, e))

        if not options.ask_vault_pass:
            vault_pass = tmp_vault_pass

    inventory_manager = Inventory(ctrl, vault_password=vault_pass)
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


def playbook_cmd(ctrl, argv):
    import ansible.playbook
    import ansible.constants as C
    from ansible import errors
    from ansible import callbacks
    from ansible import utils
    from ansible.color import ANSIBLE_COLOR, stringc
    from ansible.utils.vault import VaultLib
    from ploy_ansible import ansible_version
    from ploy_ansible.inventory1 import Inventory

    parser = utils.base_parser(
        constants=C,
        connect_opts=True,
        runas_opts=True,
        subset_opts=True,
        check_opts=True,
        diff_opts=True,
        usage='%s playbook playbook.yml' % ctrl.progname
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
        patch_connect(ctrl)
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
                vault_pass = get_vault_password_source(ctrl.config).get()
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
                except (OSError, IOError) as e:
                    raise errors.AnsibleError("Could not read %s: %s" % (this_path, e))

                if not options.ask_vault_pass:
                    vault_pass = tmp_vault_pass
        inventory = Inventory(ctrl, vault_password=vault_pass)
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
                print('')
                print('playbook: %s' % playbook)
                print('')
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
                        print('  play #%d (%s): host count=%d' % (playnum, label, len(hosts)))
                        for host in hosts:
                            print('    %s' % host)

                    if options.listtasks:
                        print('  play #%d (%s):' % (playnum, label))

                        for task in play.tasks():
                            _only_tags = set(task.tags).intersection(pb.only_tags)
                            _skip_tags = set(task.tags).intersection(pb.skip_tags)
                            if (_only_tags and not _skip_tags):
                                if getattr(task, 'name', None) is not None:
                                    # meta tasks have no names
                                    print('    %s' % task.name)
                    print('')
                continue

            if options.syntax:
                # if we've not exited by now then we are fine.
                print('Playbook Syntax is fine')
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

            print("")
            if len(failed_hosts) > 0:
                sys.exit(2)
            if len(unreachable_hosts) > 0:
                sys.exit(3)
    except errors.AnsibleError as e:
        callbacks.display("ERROR: %s" % e, color='red', stderr=True)
        sys.exit(1)


def run_cli(ctrl, name, argv):
    if name == 'ansible':
        return ansible_cmd(ctrl, argv)
    elif name == 'playbook':
        return playbook_cmd(ctrl, argv)
    raise NotImplementedError
