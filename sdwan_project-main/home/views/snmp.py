from django.shortcuts import render, HttpResponse, redirect
from datetime import datetime
from home.models import Contact
from django.contrib import messages
from django.http import JsonResponse
import subprocess
import os


def snmp(request):
    return render(request, "snmp.html")