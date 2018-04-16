"""
Author: Daniele Linguagossa

Heap CTF binary fuzzing made easy
"""
from pwn import *
import random
import struct
import re
import os


class Vulnerability():
    vulns = {
        '1': 'HEAP WRITE OOB',
        '2': 'HEAP READ OOB',
        '3': 'FREE NON ALLOC',
        '4': 'DOUBLE FREE',
        '5': 'USE_AFTER_FREE',
        '6': 'SEGMENTATION FAULT'
    }

    def __init__(self, data):
        data = data.split("-")
        self.kind = data[0]
        self.addr = data[1]
        self.orgsize = data[2]
        self.newsize = data[3]

    def __str__(self):
        return "Found {} on {} size: {} new size: {}".format(self.vulns[self.kind], self.addr, self.orgsize,
                                                             self.newsize)


class SELF():
    pass


class InputType():
    STRING = 1
    NUMBER = 2
    FORMAT = 3
    CHOICE = 4


class ProcessRestart():
    pass


class Input():
    format_re = re.compile('(%[a-z])')
    string_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    def __init__(self, kind=None, choice=None, min=1, max=10, send_after=">", format=None, newline=True, end="\n",
                 after=None, map_choice=None):
        self.type = kind
        self.choice = choice
        self.send_after = send_after
        self.format = format
        self.newline = newline
        self.end = end
        self.after = after
        self.map_choice = map_choice
        self.max = max
        self.min = min

    def _send(self, data, newline, callback):
        callback(data, newline)
        try:
            if newline:
                self.process.sendline(data)
            else:
                self.process.send_raw(data)
        except:
            pass

    def _read_until(self):
        try:
            self.process.readuntil(self.send_after)
        except:
            pass

    def _apply_post_hook(self, data):
        if not self.newline:
            data += self.end
        return data

    def _random_string(self, post_hook=True):
        s = ""
        l = random.randint(self.min, self.max)
        for i in range(0, l):
            s += self.string_charset[random.randint(0, len(self.string_charset) - 1)]
        if post_hook:
            return self._apply_post_hook(s)
        else:
            return s

    def _random_int(self, post_hook=True):
        n = random.randint(self.min, int(self.max))
        if post_hook:
            return self._apply_post_hook(str(n))
        else:
            return str(n)

    def _random_format(self):
        matches = self.format_re.findall(self.format)
        data = self.format
        for match in matches:
            if match == "%s":
                data = data.replace(match, self._random_string(post_hook=False), 1)
            else:
                data = str(data).replace(match, self._random_int(post_hook=False), 1)
        return self._apply_post_hook(data)

    def add_map_choice(self, map_choice):
        self.map_choice = map_choice

    def add_after(self, after):
        self.after = after

    def run(self, process, callback):
        poll = process.poll()
        if poll != None:
            process.close()
            return ProcessRestart()
        self.process = process
        self._read_until()
        if self.type == InputType.STRING:
            self._send(self._random_string(), self.newline, callback)
            return self.after
        elif self.type == InputType.CHOICE:
            if self.choice is not None:
                idx = random.randint(0, len(self.choice) - 1)
                self._send(self.choice[idx], self.newline, callback)
                if isinstance(self.map_choice[idx], SELF):
                    return self
                else:
                    return self.map_choice[idx]
        elif self.type == InputType.NUMBER:
            self._send(self._random_int(), self.newline, callback)
            return self.after
        elif self.type == InputType.FORMAT:
            self._send(self._random_format(), self.newline, callback)
            return self.after

class HeapFuzz():
    def __init__(self, bin, pipe="/tmp/heapfuzz", preload_lib="./heapfuzz.so"):
        self.preload_lib = preload_lib
        self._configure()
        self.process = process(bin)
        self.pipe_name = pipe
        self.bin = bin
        self._open_pipe()
        self.vulnerabilities = {}
        self.trigger = []

    def _configure(self):
        with open('/proc/sys/kernel/randomize_va_space', 'r') as aslr:
            enabled = int(aslr.read())
            if enabled:
                log.warn("Please disable ASLR with 'echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'!")
                sys.exit(0)
            aslr.close()
        context.log_level = "warn"
        os.environ["LD_PRELOAD"] = self.preload_lib
        os.environ["USE_HEAPFUZZ"] = "1"

    def _open_pipe(self):
        self.pipe_fd = os.open(self.pipe_name, os.O_RDONLY | os.O_NONBLOCK)

    def _restart(self):
        try:
            self.process.close()
        except: pass
        self.process = process(self.bin)
        os.close(self.pipe_fd)
        self._open_pipe()
        self.trigger = []

    def _read_from_pipe(self):
        try:
            l = os.read(self.pipe_fd, 4)
            length = struct.unpack("<I", l)[0]
            data = os.read(self.pipe_fd, length)
            return data
        except:
            pass

    def _parse_vulnerability(self, data):
        if data:
            l = str(Vulnerability(data))
            try:
                self.vulnerabilities[hash(l)]
            except KeyError:
                self.vulnerabilities.update({hash(l): self.trigger})
                log.warn(Vulnerability(data))
                log.warn("Triggered with:\n"+"\t"+"\n\t".join(self.trigger)+"\n")

    def _send_callback(self, data, newline):
        self.trigger.append("Sending '{}' {}".format(data, "with newline" if newline else "without newline"))

    def start(self, init):
        ret = init.run(self.process, self._send_callback)
        while True:
            try:
                if ret is None:
                    break
                elif isinstance(ret, ProcessRestart):
                    self._restart()
                    ret = init.run(self.process, self._send_callback)
                else:
                    self._parse_vulnerability(self._read_from_pipe())
                    ret = ret.run(self.process, self._send_callback)
            except KeyboardInterrupt:
                self.process.close()
                exit(0)

