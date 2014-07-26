from ansible import errors
from ansible import utils
from ansible.callbacks import vvv
from ploy_ansible import remote
import execnet
import os
import pipes
import sys


class RPCWrapper(object):

    def __init__(self, channel):
        self.channel = channel

    def __getattr__(self, name):
        def call(*args, **kw):
            self.channel.send((name, args, kw))
            result = self.channel.receive()
            try:
                result[0]
            except (TypeError, IndexError):
                pass
            else:
                if result[0] == 'remote-core-error':
                    print >>sys.stderr, result[1]
                    raise RuntimeError('Remote exception encountered.')
            return result
        return call


class SSHArgs:
    def __init__(self, args):
        self.args = args

    def split(self):
        return self.args


RPC_CACHE = {}


class Connection(object):
    ''' execnet based connections '''

    def __init__(self, runner, host, port, user, password, private_key_file, *args, **kwargs):
        self.runner = runner
        self.host = host
        self.user = user
        self.has_pipelining = False
        self._cache_key = (host, user)

    def connect(self):
        if self._cache_key not in RPC_CACHE:
            ctrl = self.runner._ploy_ctrl
            instance = ctrl.instances[self.host]
            if hasattr(instance, '_status'):
                if instance._status() != 'running':
                    raise errors.AnsibleError("Instance '%s' unavailable." % instance.config_id)
            try:
                ssh_info = instance.init_ssh_key(user=self.user)
            except instance.paramiko.SSHException as e:
                raise errors.AnsibleError("Couldn't validate fingerprint for '%s': %s" % (instance.config_id, e))
            spec = execnet.XSpec('ssh')
            ssh_args = instance.ssh_args_from_info(ssh_info)
            if utils.VERBOSITY > 3:
                ssh_args += ["-vvv"]
            spec.ssh = SSHArgs(ssh_args)
            vars = self.runner.inventory.get_variables(self.host)
            spec.python = vars.get('ansible_python_interpreter', 'python')
            gw = execnet.makegateway(spec)
            channel = gw.remote_exec(remote)
            RPC_CACHE[self._cache_key] = RPCWrapper(channel)
        self.rpc = RPC_CACHE[self._cache_key]
        return self

    def exec_command(self, cmd, tmp_path, sudo_user, sudoable=False, executable='/bin/sh', in_data=None, su=None, su_user=None):
        if su or su_user:
            raise errors.AnsibleError("Internal Error: this module does not support running commands via su")

        if in_data:
            raise errors.AnsibleError("Internal Error: this module does not support optimized module pipelining")

        remote_cmd = []
        if not self.runner.sudo or not sudoable:
            if executable:
                remote_cmd.append(executable + ' -c ' + pipes.quote(cmd))
            else:
                remote_cmd.append(cmd)
        else:
            sudocmd, prompt, success_key = utils.make_sudo_cmd(sudo_user, executable, cmd)
            remote_cmd.append(sudocmd)
        remote_cmd = ' '.join(remote_cmd)
        vvv("execnet exec_command %r" % remote_cmd)
        rc, stdout, stderr = self.rpc.exec_command(remote_cmd)
        return (rc, '', stdout, stderr)

    def put_file(self, in_path, out_path):
        vvv("execnet put_file %r %r" % (in_path, out_path))
        if not os.path.exists(in_path):
            raise errors.AnsibleFileNotFound("file or module does not exist: %s" % in_path)
        with open(in_path) as f:
            self.rpc.put_file(f.read(), out_path)

    def fetch_file(self, in_path, out_path):
        vvv("execnet fetch_file %r %r" % (in_path, out_path))
        data = self.rpc.fetch_file(in_path)
        with os.path.open(out_path, 'w') as f:
            f.write(data)

    def close(self):
        pass
