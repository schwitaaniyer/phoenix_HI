import asyncio
import os
import pty
import subprocess
from channels.generic.websocket import AsyncWebsocketConsumer

class VtyshConsoleConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.pty_pid, self.pty_fd = pty.fork()
        if self.pty_pid == 0:
            # Child process: replace with vtysh
            os.execvp('vtysh', ['vtysh'])
        else:
            await self.accept()
            self.loop = asyncio.get_event_loop()
            self.read_task = self.loop.create_task(self.read_pty())

    async def disconnect(self, close_code):
        if hasattr(self, 'read_task'):
            self.read_task.cancel()
        if hasattr(self, 'pty_fd'):
            os.close(self.pty_fd)

    async def receive(self, text_data=None, bytes_data=None):
        if text_data:
            os.write(self.pty_fd, text_data.encode())

    async def read_pty(self):
        try:
            while True:
                await asyncio.sleep(0.01)
                if self.pty_fd:
                    data = os.read(self.pty_fd, 1024)
                    if data:
                        await self.send(text_data=data.decode(errors='ignore'))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.send(text_data=f'\n[PTY ERROR] {e}\n') 