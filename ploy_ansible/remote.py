import subprocess
import traceback


try:
    string_types = basestring
except NameError:
    string_types = str


# Satisfy flake8 and support testing.
try:
    channel
except NameError:
    channel = None


def exec_command(cmd):
    p = subprocess.Popen(
        cmd, shell=isinstance(cmd, string_types),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)


def put_file(data, out_path):
    with open(out_path, 'wb') as f:
        f.write(data)


def fetch_file(in_path):
    with open(in_path, 'rb') as f:
        return f.read()


if __name__ == '__channelexec__':
    while not channel.isclosed():
        task, args, kw = channel.receive()
        try:
            result = locals()[task](*args, **kw)
        except Exception:
            tb = traceback.format_exc()
            result = ('remote-core-error', tb)
        channel.send(result)
