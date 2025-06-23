from django.shortcuts import render, redirect
from django.views import View
from django.urls import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
import subprocess

class RoutingView(LoginRequiredMixin, View):
    def get(self, request):
        # Get routing tables
        try:
            basic_routes = subprocess.check_output(['ip', 'route', 'show']).decode('utf-8')
            advanced_routes = subprocess.check_output(['ip', 'route', 'show', 'table', 'all']).decode('utf-8')
            app_routes = subprocess.check_output(['nft', 'list', 'ruleset']).decode('utf-8')
            mesh_status = subprocess.check_output(['vtysh', '-c', 'show ip nhrp']).decode('utf-8')
        except Exception as e:
            basic_routes = f"Error: {str(e)}"
            advanced_routes = f"Error: {str(e)}"
            app_routes = f"Error: {str(e)}"
            mesh_status = f"Error: {str(e)}"
        
        return render(request, 'network/routing.html', {
            'basic_routes': basic_routes,
            'advanced_routes': advanced_routes,
            'app_routes': app_routes,
            'mesh_status': mesh_status,
            'active_tab': request.GET.get('tab', 'basic')
        })
    
    def post(self, request):
        tab = request.POST.get('tab', 'basic')
        action = request.POST.get('action')
        
        if tab == 'basic' and action == 'add_route':
            # Add basic route logic
            network = request.POST.get('network')
            gateway = request.POST.get('gateway')
            try:
                subprocess.run(['ip', 'route', 'add', network, 'via', gateway], check=True)
            except subprocess.CalledProcessError as e:
                pass
        
        elif tab == 'mesh' and action == 'add_mesh':
            # Add mesh configuration logic
            pass
            
        return redirect(f'{reverse("network:routing")}?tab={tab}')