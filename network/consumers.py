import asyncio
import os
import pty
import subprocess
from channels.generic.websocket import AsyncWebsocketConsumer
import logging

class VtyshConsoleConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logging.info('VtyshConsoleConsumer: connect called')
        try:
            self.pty_pid, self.pty_fd = pty.fork()
            if self.pty_pid == 0:
                logging.info('VtyshConsoleConsumer: in child process, exec vtysh')
                os.execvp('vtysh', ['vtysh'])
            else:
                await self.accept()
                self.loop = asyncio.get_event_loop()
                self.read_task = self.loop.create_task(self.read_pty())
                logging.info(f'VtyshConsoleConsumer: PTY started with pid {self.pty_pid}, fd {self.pty_fd}')
        except Exception as e:
            logging.error(f'VtyshConsoleConsumer: connect error: {e}')
            await self.close()

    async def disconnect(self, close_code):
        logging.info(f'VtyshConsoleConsumer: disconnect called, close_code={close_code}')
        if hasattr(self, 'read_task'):
            self.read_task.cancel()
        if hasattr(self, 'pty_fd'):
            try:
                os.close(self.pty_fd)
                logging.info('VtyshConsoleConsumer: PTY fd closed')
            except Exception as e:
                logging.error(f'VtyshConsoleConsumer: error closing PTY fd: {e}')

    async def receive(self, text_data=None, bytes_data=None):
        logging.info(f'VtyshConsoleConsumer: receive called, text_data={text_data}')
        if text_data:
            try:
                os.write(self.pty_fd, text_data.encode())
                logging.info(f'VtyshConsoleConsumer: wrote to PTY: {text_data}')
            except Exception as e:
                logging.error(f'VtyshConsoleConsumer: error writing to PTY: {e}')

    async def read_pty(self):
        try:
            while True:
                await asyncio.sleep(0.01)
                if self.pty_fd:
                    try:
                        data = os.read(self.pty_fd, 1024)
                        if data:
                            await self.send(text_data=data.decode(errors='ignore'))
                            logging.info(f'VtyshConsoleConsumer: sent data from PTY: {data[:40]}...')
                    except Exception as e:
                        logging.error(f'VtyshConsoleConsumer: error reading from PTY: {e}')
                        await self.send(text_data=f'\n[PTY ERROR] {e}\n')
                        break
        except asyncio.CancelledError:
            logging.info('VtyshConsoleConsumer: read_pty cancelled')
        except Exception as e:
            logging.error(f'VtyshConsoleConsumer: read_pty error: {e}')
            await self.send(text_data=f'\n[PTY ERROR] {e}\n') 