from django.shortcuts import render

# Create your views here.

def vtysh(request)

            try:
                result = subprocess.check_output(f"vtysh", shell=True).decode()
                output = result.stdout
            except FileNotFoundError:
                output = "Error vtysh not found"

            return render(request, "routing.html", {"output":output})