from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
import subprocess

class TerminalView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'terminal/index.html')
    
    def post(self, request):
        command = request.POST.get('command', '')
        output = ""
        
        if command:
            try:
                # Limit allowed commands for security
                ALLOWED_COMMANDS = [
                    'ls', 'cd', 'pwd', 'cat', 'grep', 'ping', 'traceroute',
                    'ip', 'ifconfig', 'netstat', 'ps', 'top', 'df', 'free',
                    'uptime', 'uname', 'whoami'
                ]
                
                cmd_parts = command.split()
                if cmd_parts[0] not in ALLOWED_COMMANDS:
                    output = f"Command not allowed: {cmd_parts[0]}"
                else:
                    output = subprocess.check_output(
                        cmd_parts,
                        stderr=subprocess.STDOUT,
                        timeout=10
                    ).decode('utf-8')
            except subprocess.TimeoutExpired:
                output = "Command timed out"
            except subprocess.CalledProcessError as e:
                output = e.output.decode('utf-8')
            except Exception as e:
                output = str(e)
        
        return JsonResponse({
            'command': command,
            'output': output
        })