from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
import subprocess

class OptimisationView(LoginRequiredMixin, View):
    def get(self, request):
        # Get current optimisation settings
        try:
            compression = subprocess.check_output(['cat', '/sys/module/zstd/parameters/compression_level']).decode('utf-8').strip()
            fec_status = subprocess.check_output(['systemctl', 'is-active', 'raptorq']).decode('utf-8').strip()
            cc_algo = subprocess.check_output(['sysctl', 'net.ipv4.tcp_congestion_control']).decode('utf-8').strip()
            shaping_rules = subprocess.check_output(['tc', 'qdisc', 'show']).decode('utf-8')
            qos_rules = subprocess.check_output(['nft', 'list', 'chain', 'ip', 'qos', 'qos_chain']).decode('utf-8')
        except Exception as e:
            compression = "Unknown"
            fec_status = "Unknown"
            cc_algo = "Unknown"
            shaping_rules = f"Error: {str(e)}"
            qos_rules = f"Error: {str(e)}"
        
        return render(request, 'network/optimisation.html', {
            'compression': compression,
            'fec_status': fec_status,
            'cc_algo': cc_algo.split('=')[-1] if '=' in cc_algo else cc_algo,
            'shaping_rules': shaping_rules,
            'qos_rules': qos_rules,
            'active_tab': request.GET.get('tab', 'compression')
        })
    
    def post(self, request):
        tab = request.POST.get('tab', 'compression')
        
        if tab == 'compression':
            level = request.POST.get('level')
            if level:
                try:
                    subprocess.run(['echo', level, '>', '/sys/module/zstd/parameters/compression_level'], shell=True)
                except:
                    pass
        
        elif tab == 'qos':
            # Handle QoS configuration
            pass
            
        return redirect(f'{reverse("network:optimisation")}?tab={tab}')