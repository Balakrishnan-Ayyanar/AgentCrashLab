"""Public candidate tests are offline by construction, not just by convention."""
import asyncio
import socket
import subprocess
from pathlib import Path
import pytest

@pytest.fixture(autouse=True)
def deny_external_network_and_docker(monkeypatch):
    original=socket.socket.connect
    def connect(sock,address):
        if sock.family in (socket.AF_INET,socket.AF_INET6):
            raise AssertionError('Network prohibited in offline tests')
        return original(sock,address)
    monkeypatch.setattr(socket.socket,'connect',connect)
    original_process=asyncio.create_subprocess_exec
    async def process(command,*args,**kwargs):
        if Path(str(command)).name=='docker':
            raise AssertionError('Actual Docker prohibited in offline tests')
        return await original_process(command,*args,**kwargs)
    monkeypatch.setattr(asyncio,'create_subprocess_exec',process)

    original_popen = subprocess.Popen
    def popen(command, *args, **kwargs):
        first = command[0] if isinstance(command, (list, tuple)) else str(command).split()[0]
        if Path(str(first)).name == 'docker':
            raise AssertionError('Actual Docker prohibited in offline tests')
        return original_popen(command, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', popen)
