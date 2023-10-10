from ansible import errors
from ansible.plugins.connection import ConnectionBase
from execnet.gateway_base import _Serializer
import os


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
        self._mp_helper = self._play_context._ploy_ctrl._mp_helper

    def _connect(self):
        ctrl = self._play_context._ploy_ctrl
        self.rpc = self._mp_helper.connect(ctrl.instances[self.host], self.port, self.user)
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
