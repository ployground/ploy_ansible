from __future__ import print_function
from ansible import errors
from ansible.plugins.connection import ConnectionBase
from execnet.gateway_base import _Serializer
import execnet
import os
import paramiko
import ploy_ansible
import ploy_ansible.remote
import sys

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


# monkey patch execnet serializer to support AnsibleUnsafeText
if not hasattr(_Serializer, 'save_AnsibleUnsafeText'):
    def save_AnsibleUnsafeText(self, s):
        self._save(u"%s" % s)
    _Serializer.save_AnsibleUnsafeText = save_AnsibleUnsafeText


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
                    print(result[1], file=sys.stderr)
                    raise RuntimeError('Remote exception encountered.')
            return result
        return call


class SSHArgs:
    def __init__(self, args):
        self.args = args

    def split(self):
        return self.args


class Connection(ConnectionBase):
    ''' execnet based connections '''

    transport = 'execnet'

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)

        self.host = self._play_context.remote_addr
        if hasattr(self.host, 'instance'):
            self.host = self.host.instance.uid
        self.port = self._play_context.port
        self.user = self._play_context.remote_user
        self.has_pipelining = False
        self.become_methods_supported = ['sudo']
        self._cache_key = (self.host, self.port, self.user)

    def _connect(self):
        if self._cache_key not in ploy_ansible.RPC_CACHE:
            ctrl = self._play_context._ploy_ctrl
            instance = ctrl.instances[self.host]
            if hasattr(instance, '_status'):
                if instance._status() != 'running':
                    raise errors.AnsibleError("Instance '%s' unavailable." % instance.config_id)
            try:
                ssh_info = instance.init_ssh_key(user=self.user)
            except paramiko.SSHException as e:
                raise errors.AnsibleError("Couldn't validate fingerprint for '%s': %s" % (instance.config_id, e))
            spec = execnet.XSpec('ssh')
            ssh_args = instance.ssh_args_from_info(ssh_info)
            if display.verbosity > 3:
                ssh_args += ["-vvv"]
            spec.ssh = SSHArgs(ssh_args)
            vars = instance.get_ansible_variables()
            spec.python = vars.get('ansible_python_interpreter', 'python')
            gw = execnet.makegateway(spec)
            try:
                channel = gw.remote_exec(ploy_ansible.remote)
            except IOError as e:
                raise errors.AnsibleError("Couldn't open execnet channel for '%s': %s" % (instance.config_id, e))
            ploy_ansible.RPC_CACHE[self._cache_key] = RPCWrapper(channel)
        self.rpc = ploy_ansible.RPC_CACHE[self._cache_key]
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        if in_data is not None:
            raise errors.AnsibleError("Internal Error: this module does not support optimized module pipelining")

        display.vvv("execnet exec_command %s" % cmd)
        rc, stdout, stderr = self.rpc.exec_command(cmd)
        return (rc, stdout, stderr)

    def put_file(self, in_path, out_path):
        display.vvv("execnet put_file %r %r" % (in_path, out_path))
        if not os.path.exists(in_path):
            raise errors.AnsibleFileNotFound("file or module does not exist: %s" % in_path)
        with open(in_path, "rb") as f:
            self.rpc.put_file(f.read(), out_path)

    def fetch_file(self, in_path, out_path):
        display.vvv("execnet fetch_file %r %r" % (in_path, out_path))
        data = self.rpc.fetch_file(in_path)
        with os.path.open(out_path, 'wb') as f:
            f.write(data)

    def close(self):
        pass
