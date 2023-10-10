from __future__ import print_function
from lazy import lazy
import atexit
import ploy_ansible
import sys
import threading
try:
    from queue import Empty
except ImportError:
    from Queue import Empty


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


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


class MPConnection:
    def __init__(self, ctrl, key, queue, receiver, sender):
        self._key = key
        self._queue = queue
        self._receiver = receiver
        self._sender = sender

    def exec_command(self, cmd):
        self._queue.put(('exec_command', dict(key=self._key, pipe=self._sender, cmd=cmd)))
        result = self._receiver.recv()
        if isinstance(result, BaseException):
            raise result
        return result

    def fetch_file(self, path):
        self._queue.put(('fetch_file', dict(key=self._key, pipe=self._sender, path=path)))
        result = self._receiver.recv()
        if isinstance(result, BaseException):
            raise result
        return result

    def put_file(self, data, path):
        self._queue.put(('put_file', dict(key=self._key, pipe=self._sender, data=data, path=path)))
        result = self._receiver.recv()
        if isinstance(result, BaseException):
            raise result
        return result


class MPHelper:
    def __init__(self, ctrl):
        self.ctrl = ctrl
        manager = self.mpcontext.Manager()
        self._queue = manager.Queue()
        self._shutdown = threading.Event()
        self.thread = threading.Thread(
            target=self.run, name='MPHelperThread')
        self.thread.daemon = True
        self.thread.start()
        self._connections = {}
        atexit.register(self.close)

    @lazy
    def AnsibleError(self):
        from ansible.errors import AnsibleError
        return AnsibleError

    @lazy
    def SSHException(self):
        from paramiko import SSHException
        return SSHException

    @lazy
    def execnet(self):
        import execnet
        return execnet

    @lazy
    def remote(self):
        from ploy_ansible import remote
        return remote

    def close(self):
        self._shutdown.set()
        self.thread.join()

    def connect(self, instance, port, user):
        key = (instance.uid, port, user)
        if key not in self._connections:
            (receiver, sender) = self.mpcontext.Pipe()
            self._connections[key] = MPConnection(self.ctrl, key, self._queue, receiver, sender)
        return self._connections[key]

    def create(self, key):
        if key not in ploy_ansible.RPC_CACHE:
            ctrl = self.ctrl
            (host, port, user) = key
            instance = ctrl.instances[host]
            chan = instance.conn.get_transport().open_session()
            rin = chan.makefile('wb', -1)
            rout = chan.makefile('rb', -1)
            spec = self.execnet.XSpec('ssh')
            self.execnet.default_group.allocate_id(spec)
            spec.execmodel = self.execnet.default_group.remote_execmodel.backend
            vars = instance.get_ansible_variables()
            spec.python = vars.get('ansible_python_interpreter', 'python')
            chan.exec_command('%s -c "%s"' % (spec.python, self.execnet.gateway_io.popen_bootstrapline))
            io = self.execnet.gateway_base.Popen2IO(rin, rout, self.execnet.default_group.execmodel)
            self.execnet.gateway_bootstrap.bootstrap_exec(io, spec)
            gw = self.execnet.gateway.Gateway(io, spec)
            try:
                channel = gw.remote_exec(self.remote)
            except IOError as e:
                raise self.AnsibleError("Couldn't open execnet channel for '%s': %s" % (instance.config_id, e))
            ploy_ansible.RPC_CACHE[key] = RPCWrapper(channel)
        return ploy_ansible.RPC_CACHE[key]

    @lazy
    def mpcontext(self):
        try:
            from ansible.utils.multiprocessing import context
        except ImportError:
            import multiprocessing as context
        return context

    def process(self, item):
        (kind, data) = item
        try:
            if kind == 'exec_command':
                rpc = self.create(data['key'])
                result = rpc.exec_command(data['cmd'])
                data['pipe'].send(result)
            elif kind == 'fetch_file':
                rpc = self.create(data['key'])
                result = rpc.fetch_file(data['path'])
                data['pipe'].send(result)
            elif kind == 'put_file':
                rpc = self.create(data['key'])
                result = rpc.put_file(data['data'], data['path'])
                data['pipe'].send(result)
            else:
                raise RuntimeError("Unknown kind of item %s" % repr(item))
        except BaseException as e:
            data['pipe'].send(e)

    def run(self):
        while 1:
            if self._shutdown.is_set():
                break
            try:
                item = self._queue.get(timeout=1)
            except Empty:
                continue
            except Exception:
                break
            self.process(item)
