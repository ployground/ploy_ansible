from __future__ import print_function, unicode_literals
from operator import attrgetter
import argparse
import getpass
import logging
import pkg_resources
import os
import subprocess
import sys
from binascii import b2a_base64
from ploy.common import sorted_choices, yesno


notset = object()


try:
    string_types = basestring
except NameError:
    string_types = str


ansible_dist = pkg_resources.get_distribution("ansible")
ansible_version = ansible_dist.parsed_version
ANSIBLE1 = ansible_version < pkg_resources.parse_version("2dev")
ANSIBLE2 = not ANSIBLE1
ANSIBLE_HAS_CONTEXT = ansible_version >= pkg_resources.parse_version("2.8dev")
ANSIBLE_HAS_SENTINEL = ansible_version >= pkg_resources.parse_version("2.8dev")
log = logging.getLogger('ploy_ansible')
RPC_CACHE = {}


ansible_paths = dict(
    lookup=[os.path.join(os.path.abspath(os.path.dirname(__file__)), 'lookup_plugins')])

if ANSIBLE1:
    ansible_paths['connection'] = [os.path.join(
        os.path.abspath(os.path.dirname(__file__)), 'ansible1_connection_plugins')]
else:
    ansible_paths['connection'] = [os.path.join(
        os.path.abspath(os.path.dirname(__file__)), 'connection_plugins')]


def inject_ctrl(ctrl):
    # we need to inject ``ctrl`` as ``_ploy_ctrl``, so the respective classes
    # have access to it
    if not ANSIBLE2 or ctrl is None:
        return
    from ansible.playbook.play_context import PlayContext
    from ploy_ansible.inventory import InventoryManager
    PlayContext._ploy_ctrl = ctrl
    InventoryManager._ploy_ctrl = ctrl


def inject_ansible_paths(ctrl=None):
    if getattr(inject_ansible_paths, 'done', False):
        inject_ctrl(ctrl)
        return
    # collect and inject ansible paths (roles and library) from entrypoints
    try:
        import ansible.constants as C
    except ImportError:
        log.error("Can't import ansible, check whether it's installed correctly.")
        sys.exit(1)
    if ansible_version >= pkg_resources.parse_version("2.8dev"):
        log.warn(
            "You are using an untested version %s of ansible. "
            "The latest tested version is 2.7.X. "
            "Any errors may be caused by that newer version." % ansible_version)
    if ANSIBLE2:
        # we need to set ``display`` up globally and on the ``__main__`` module
        # for verbosity settings etc to work properly
        from ansible.utils.display import Display
        global display
        try:
            display
        except NameError:
            display = sys.modules['__main__'].display = Display()
        else:
            sys.modules['__main__'].display = display
    # get the paths
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
    # and inject the paths
    if ANSIBLE1:
        if C.DEFAULT_ROLES_PATH is None:
            C.DEFAULT_ROLES_PATH = os.path.pathsep.join(extra_roles)
        else:
            C.DEFAULT_ROLES_PATH = os.path.pathsep.join(extra_roles + [C.DEFAULT_ROLES_PATH])
        if C.DEFAULT_MODULE_PATH is None:
            C.DEFAULT_MODULE_PATH = os.path.pathsep.join(extra_library)
        else:
            C.DEFAULT_MODULE_PATH = os.path.pathsep.join(extra_library + [C.DEFAULT_MODULE_PATH])
        for attr in extra_plugins:
            setattr(C, attr, os.path.pathsep.join([os.path.pathsep.join(extra_plugins[attr]), getattr(C, attr)]))
    else:
        C.DEFAULT_ROLES_PATH[0:0] = extra_roles
        C.DEFAULT_MODULE_PATH[0:0] = extra_library
        C.DEFAULT_TRANSPORT = 'execnet_connection'
        for attr in extra_plugins:
            getattr(C, attr)[0:0] = extra_plugins[attr]
    inject_ctrl(ctrl)
    if ANSIBLE2:
        # patch the InventoryManager into Ansible
        import ansible.inventory.manager
        from ploy_ansible.inventory import InventoryManager
        ansible.inventory.manager.InventoryManager = InventoryManager
    inject_ansible_paths.done = True


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
            log.error("No unique id for vault password in keyring specified.")
            sys.exit(1)
        self.id = id

    @property
    def bytes(self):
        return self.get().encode('ascii')

    def get(self, fail_on_error=True):
        result = getattr(self, 'key', notset)
        if result is notset:
            self.key = result = self.keyring.get_password("ploy_ansible", self.id)
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
    cache = getattr(main_config, 'ansible_vault_password_source_cache', notset)
    if cache is notset:
        main_config.ansible_vault_password_source_cache = cache = {}
    src = ansible_config.get(option)
    if src not in cache:
        if src is None:
            result = NullSource()
        else:
            result = KeyringSource(src)
        cache[src] = result
    else:
        result = cache[src]
    return result


def run_cli(ctrl, name, sub, argv, myclass=None):
    inject_ansible_paths(ctrl)
    if ANSIBLE1:
        import ploy_ansible.cli1
        return ploy_ansible.cli1.run_cli(ctrl, name, argv)
    import ansible.constants as C
    from ansible import errors
    from ansible.cli import CLI
    from ansible.module_utils._text import to_text
    import shutil
    if myclass is None:
        myclass = "%sCLI" % sub.capitalize()

    def setup_vault_secrets(loader, vault_ids, *args, **kwargs):
        vault_secret = get_vault_password_source(ctrl.config)
        if isinstance(vault_secret, NullSource):
            return []
        return [(vault_secret.id, vault_secret)]
    CLI.setup_vault_secrets = staticmethod(setup_vault_secrets)

    mycli = getattr(
        __import__("ansible.cli.%s" % sub, fromlist=[myclass]),
        myclass)
    try:
        cli = mycli(["%s %s" % (ctrl.progname, name)] + argv)
        cli.parse()
        exit_code = cli.run()
    except errors.AnsibleOptionsError as e:
        cli.parser.print_help()
        display.error(to_text(e), wrap_text=False)
        exit_code = 5
    except errors.AnsibleParserError as e:
        display.error(to_text(e), wrap_text=False)
        exit_code = 4
    except errors.AnsibleError as e:
        display.error(to_text(e), wrap_text=False)
        exit_code = 1
    except KeyboardInterrupt:
        display.error("User interrupted execution")
        exit_code = 99
    finally:
        if ANSIBLE_HAS_CONTEXT:
            from ansible.utils import context_objects
            # Reset the stored command line args
            context_objects.GlobalCLIArgs._Singleton__instance = None
        # Remove ansible tempdir
        shutil.rmtree(C.DEFAULT_LOCAL_TMP, True)
    if exit_code != 0:
        sys.exit(exit_code)


class AnsibleCmd(object):
    """Run Ansible"""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        return run_cli(self.ctrl, 'ansible', 'adhoc', argv, myclass='AdHocCLI')


class AnsiblePlaybookCmd(object):
    """Run Ansible playbook"""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        return run_cli(self.ctrl, 'playbook', 'playbook', argv)


class AnsibleConfigureCmd(object):
    """Configure an instance (ansible playbook run) after it has been started."""

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_completion(self):
        instances = set()
        for instance in self.ctrl.instances:
            if self.ctrl.instances[instance].has_playbook():
                instances.add(instance)
        return sorted_choices(instances)

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
            type=str,
            choices=self.get_completion())
        args = parser.parse_args(argv)
        instance = self.ctrl.instances[args.instance[0]]
        only_tags = args.only_tags.split(",")
        skip_tags = args.skip_tags
        if skip_tags is not None:
            skip_tags = skip_tags.split(",")
        else:
            skip_tags = []
        inject_ansible_paths(self.ctrl)
        if ANSIBLE1:
            from ploy_ansible.cli1 import parse_extra_vars
            extra_vars = parse_extra_vars(args.extra_vars)
            kwargs = dict(
                only_tags=only_tags,
                skip_tags=skip_tags,
                extra_vars=extra_vars,
                verbosity=args.verbose)
        else:
            display.verbosity = args.verbose
            if ANSIBLE_HAS_CONTEXT:
                from ansible import context
                context.CLIARGS._store['verbosity'] = args.verbose
                context.CLIARGS._store['tags'] = only_tags
                context.CLIARGS._store['skip_tags'] = skip_tags
                context.CLIARGS._store['extra_vars'] = args.extra_vars
                kwargs = dict()
            else:
                options = AnsibleOptions()
                options.verbosity = args.verbose
                options.tags = only_tags
                options.skip_tags = skip_tags
                options.extra_vars = args.extra_vars
                kwargs = dict(options=options)
        instance.hooks.before_ansible_configure(instance)
        instance.configure(**kwargs)
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
        if ANSIBLE1:
            inventory = _get_ansible_inventory(self.ctrl, self.ctrl.config)
            groups = sorted(inventory.groups, key=attrgetter('name'))
            for group in groups:
                print(group.name)
                hosts = sorted(group.hosts, key=attrgetter('name'))
                for host in hosts:
                    print("    %s" % host.name)
                print()
        else:
            inventory = _get_ansible_inventorymanager(self.ctrl, self.ctrl.config)
            groups = inventory.get_groups_dict()
            for groupname in sorted(groups):
                print(groupname)
                hosts = groups[groupname]
                for hostname in sorted(hosts):
                    print("    %s" % hostname)
                print()


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
        key = key.replace(b'+', b'-')
        key = key.replace(b'/', b'_')
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
        if ANSIBLE1:
            return ('create', 'decrypt', 'edit', 'encrypt', 'rekey')
        from ansible.cli.vault import VaultCLI
        return sorted_choices(VaultCLI.VALID_ACTIONS)

    def __call__(self, argv, help):
        if argv[0] == 'cat' and ANSIBLE2:
            print("Using deprecated 'cat' command, use 'view' instead.", file=sys.stderr)
            argv[0] = 'view'
        return run_cli(self.ctrl, 'vault', 'vault', argv)


def has_playbook(self):
    playbooks_directory = get_playbooks_directory(self.master.main_config)
    for instance_id in (self.uid, self.id):
        playbook_path = os.path.join(playbooks_directory, '%s.yml' % instance_id)
        if os.path.exists(playbook_path):
            return True
    if 'playbook' in self.config:
        return True
    if 'roles' in self.config:
        return True
    return False


def _get_playbook1(self, *args, **kwargs):
    inject_ansible_paths(self.master.ctrl)
    import ansible.playbook
    import ansible.callbacks
    import ansible.errors
    import ansible.utils
    from ansible.utils.vault import VaultLib
    from ploy_ansible.cli1 import patch_connect
    from ploy_ansible.inventory1 import Inventory

    host = self.uid
    user = self.config.get('user', 'root')
    sudo = self.config.get('sudo')
    playbooks_directory = get_playbooks_directory(self.master.main_config)

    class PlayBook(ansible.playbook.PlayBook):
        def __init__(self, *args, **kwargs):
            self.roles = kwargs.pop('roles', None)
            if self.roles is not None:
                if isinstance(self.roles, string_types):
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
        for instance_id in (self.uid, self.id):
            playbook_path = os.path.join(playbooks_directory, '%s.yml' % instance_id)
            if os.path.exists(playbook_path):
                playbook = playbook_path
                break
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
            if isinstance(hosts, string_types):
                hosts = hosts.split(':')
            if self.uid not in hosts:
                log.warning("The host '%s' is not in the list of hosts (%s) of '%s'.", self.uid, ','.join(hosts), playbook)
                if not yesno("Do you really want to apply '%s' to the host '%s'?" % (playbook, self.uid)):
                    sys.exit(1)
        play_ds['hosts'] = [self.uid]
    return pb


def _get_playbook(self, *args, **kwargs):
    inject_ansible_paths(self.master.ctrl)
    from ansible.playbook import Play, Playbook
    import ansible.errors
    if ANSIBLE_HAS_SENTINEL:
        from ansible.utils.sentinel import Sentinel
    else:
        Sentinel = None

    (options, loader, inventory, variable_manager) = self.get_ansible_variablemanager(**kwargs)
    playbooks_directory = get_playbooks_directory(self.master.main_config)
    playbook = kwargs.pop('playbook', None)
    if playbook is None:
        for instance_id in (self.uid, self.id):
            playbook_path = os.path.join(playbooks_directory, '%s.yml' % instance_id)
            if os.path.exists(playbook_path):
                playbook = playbook_path
                break
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
    if playbook is None and roles is None:
        return None
    skip_host_check = kwargs.pop('skip_host_check', False)
    try:
        if roles is None:
            pb = Playbook.load(playbook, variable_manager=variable_manager, loader=loader)
            plays = pb.get_plays()
        else:
            if isinstance(roles, string_types):
                roles = roles.split()
            data = {
                'hosts': [self.uid],
                'roles': roles}
            plays = [Play.load(data, variable_manager=variable_manager, loader=loader)]
            pb = Playbook(loader=loader)
            pb._entries.extend(plays)
    except ansible.errors.AnsibleError as e:
        log.error("AnsibleError: %s" % e)
        sys.exit(1)
    for play in plays:
        if play._attributes.get('remote_user') is Sentinel:
            play._attributes['remote_user'] = self.config.get('user', 'root')
        if self.config.get('sudo'):
            play._attributes['sudo'] = self.config.get('sudo')
        if not skip_host_check:
            hosts = play._attributes.get('hosts', Sentinel)
            if isinstance(hosts, string_types):
                hosts = hosts.split(':')
            if hosts is Sentinel:
                hosts = {}
            if self.uid not in hosts:
                log.warning("The host '%s' is not in the list of hosts (%s) of '%s'.", self.uid, ','.join(hosts), playbook)
                if not yesno("Do you really want to apply '%s' to the host '%s'?" % (playbook, self.uid)):
                    sys.exit(1)
        play._attributes['hosts'] = [self.uid]
    return pb


def get_playbook(self, *args, **kwargs):
    if ANSIBLE1:
        return _get_playbook1(self, *args, **kwargs)
    return _get_playbook(self, *args, **kwargs)


def apply_playbook(self, playbook, *args, **kwargs):
    from ansible.executor.task_queue_manager import TaskQueueManager

    (options, loader, inventory, variable_manager) = self.get_ansible_variablemanager(**kwargs)

    tqm = None
    try:
        kwargs = dict(
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            passwords=None)
        if options is not None:
            kwargs['options'] = options
        tqm = TaskQueueManager(**kwargs)
        for play in playbook.get_plays():
            return tqm.run(play=play)
    finally:
        if tqm is not None:
            tqm.cleanup()


def _configure1(self, *args, **kwargs):
    verbosity = kwargs.pop('verbosity', 0)
    pb = self.get_playbook(*args, **kwargs)
    # we have to wait importing ansible until after get_playbook ran, so the import order is correct
    import ansible.errors
    import ansible.utils
    VERBOSITY = ansible.utils.VERBOSITY
    ansible.utils.VERBOSITY = verbosity
    try:
        result = pb.run()
        for values in result.values():
            if values.get('failures', 0):
                sys.exit(2)
            if values.get('unreachable', 0):
                sys.exit(3)
    except ansible.errors.AnsibleError as e:
        log.error("AnsibleError: %s" % e)
        sys.exit(1)
    finally:
        ansible.utils.VERBOSITY = VERBOSITY


def _configure(self, *args, **kwargs):
    (options, loader, inventory, variable_manager) = self.get_ansible_variablemanager(**kwargs)
    options = kwargs.pop('options', options)
    loader = kwargs.pop('loader', loader)
    inventory = kwargs.pop('inventory', inventory)
    variable_manager = kwargs.pop('variable_manager', variable_manager)
    pb = self.get_playbook(inventory=inventory, variable_manager=variable_manager, loader=loader, *args, **kwargs)
    if pb is None:
        log.error("No playbook or roles found.")
        sys.exit(1)
    import ansible.errors
    try:
        result = self.apply_playbook(pb, inventory=inventory, variable_manager=variable_manager, loader=loader, options=options, *args, **kwargs)
        if result:
            sys.exit(result)
    except ansible.errors.AnsibleError as e:
        log.error("AnsibleError: %s" % e)
        sys.exit(1)


def configure(self, *args, **kwargs):
    if ANSIBLE1:
        return _configure1(self, *args, **kwargs)
    return _configure(self, *args, **kwargs)


def _get_ansible_inventorymanager(ctrl, main_config):
    inject_ansible_paths(ctrl)
    from ploy_ansible.inventory import InventoryManager
    return InventoryManager()


def get_ansible_inventorymanager(self):
    return _get_ansible_inventorymanager(self.master.ctrl, self.master.main_config)


class AnsibleOptions(object):
    def __init__(self):
        from ansible import constants as C
        self.ask_vault_pass = None
        self.become = C.DEFAULT_BECOME
        self.become_method = C.DEFAULT_BECOME_METHOD
        self.become_user = C.DEFAULT_BECOME_USER
        self.check = False
        self.connection = C.DEFAULT_TRANSPORT
        self.diff = C.DIFF_ALWAYS
        self.forks = C.DEFAULT_FORKS
        self.inventory = None
        self.module_path = None
        self.vault_ids = []
        self.vault_password_files = None
        self.verbosity = C.DEFAULT_VERBOSITY


def get_ansible_variablemanager(self, **kwargs):
    from ansible.parsing.dataloader import DataLoader
    from ansible.utils.vars import load_extra_vars
    from ansible.vars.manager import VariableManager
    if 'options' in kwargs:
        options = kwargs['options']
    else:
        if ANSIBLE_HAS_CONTEXT:
            options = None
        else:
            options = AnsibleOptions()
    safe_basedir = False
    if 'loader' in kwargs:
        loader = kwargs['loader']
    else:
        loader = DataLoader()
        vault_secret = get_vault_password_source(self.master.main_config)
        if not isinstance(vault_secret, NullSource):
            loader.set_vault_secrets([(vault_secret.id, vault_secret)])
        basedir = get_playbooks_directory(self.master.ctrl.config)
        loader.set_basedir(basedir)
        safe_basedir = True
    if 'inventory' in kwargs:
        inventory = kwargs['inventory']
    else:
        inventory = self.get_ansible_inventorymanager()
    if 'variable_manager' in kwargs:
        variable_manager = kwargs['variable_manager']
    else:
        variable_manager = VariableManager(loader=loader, inventory=inventory)
        if ansible_version < pkg_resources.parse_version("2.8dev"):
            variable_manager.extra_vars = load_extra_vars(loader=loader, options=options)
        if safe_basedir:
            variable_manager.safe_basedir = True
    return (options, loader, inventory, variable_manager)


def _get_ansible_inventory(ctrl, main_config):
    inject_ansible_paths()
    from ploy_ansible.inventory1 import Inventory
    vault_password = get_vault_password_source(main_config).get(fail_on_error=False)
    return Inventory(ctrl, vault_password=vault_password)


def get_ansible_inventory(self):
    return _get_ansible_inventory(self.master.ctrl, self.master.main_config)


class AnsibleVariablesDict(dict):
    def __getitem__(self, name):
        from ansible.utils.template import template
        return template(self.basedir, dict.__getitem__(self, name), self, fail_on_undefined=True)


def _get_ansible_variables1(self):
    inventory = self.get_ansible_inventory()
    basedir = get_playbooks_directory(self.master.ctrl.config)
    result = AnsibleVariablesDict(inventory.get_variables(self.uid))
    result.basedir = basedir
    return result


def _get_ansible_variables(self):
    from ansible.vars.hostvars import HostVars

    (options, loader, inventory, variable_manager) = self.get_ansible_variablemanager()
    hostvars = HostVars(inventory=inventory, variable_manager=variable_manager, loader=loader)
    return hostvars[self.uid]


def get_ansible_variables(self):
    if ANSIBLE1:
        return _get_ansible_variables1(self)
    return _get_ansible_variables(self)


def _get_vault_lib1(ctrl, main_config):
    inject_ansible_paths(ctrl)
    from ansible.utils.vault import VaultLib
    return VaultLib(get_vault_password_source(ctrl.config).get())


def _get_vault_lib(ctrl, main_config):
    inject_ansible_paths(ctrl)
    from ansible.parsing.vault import VaultLib as BaseVaultLib
    from ansible.parsing.vault import is_encrypted

    class VaultLib(BaseVaultLib):
        # we redefine this here to get rid of the deprecation warning
        @staticmethod
        def is_encrypted(data):
            return is_encrypted(data)

    vl = VaultLib()
    vault_secret = get_vault_password_source(main_config)
    if not isinstance(vault_secret, NullSource):
        vl.secrets = [(vault_secret.id, vault_secret)]
    return vl


def get_vault_lib(self):
    if ANSIBLE1:
        return _get_vault_lib1(self.master.ctrl, self.master.main_config)
    return _get_vault_lib(self.master.ctrl, self.master.main_config)


def augment_instance(instance):
    if not hasattr(instance, 'apply_playbook'):
        instance.apply_playbook = apply_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'has_playbook'):
        instance.has_playbook = has_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'get_playbook'):
        instance.get_playbook = get_playbook.__get__(instance, instance.__class__)
    if not hasattr(instance, 'configure'):
        instance.configure = configure.__get__(instance, instance.__class__)
    if ANSIBLE2:
        if not hasattr(instance, 'get_ansible_variablemanager'):
            instance.get_ansible_variablemanager = get_ansible_variablemanager.__get__(instance, instance.__class__)
        if not hasattr(instance, 'get_ansible_inventorymanager'):
            instance.get_ansible_inventorymanager = get_ansible_inventorymanager.__get__(instance, instance.__class__)
    else:
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
        PathMassager('global', 'playbooks-directory'),
        PathMassager(None, 'playbook')]


plugin = dict(
    augment_instance=augment_instance,
    get_commands=get_commands,
    get_massagers=get_massagers)
