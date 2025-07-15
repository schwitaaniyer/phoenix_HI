from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.conf import settings
import ldap3
import requests
import logging
import socket
from tacacs_plus.client import TACACSClient
from pyrad.client import Client as RadiusClient
from pyrad.dictionary import Dictionary
import pyrad.packet

User = get_user_model()

class LocalBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None
        return None
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class LDAPBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        ldap_config = getattr(settings, 'LDAP_CONFIG', {})
        server_uri = ldap_config.get('SERVER_URI')
        base_dn = ldap_config.get('BASE_DN')
        user_dn_template = ldap_config.get('USER_DN_TEMPLATE', '{username}')
        if not (server_uri and base_dn):
            return None
        server = ldap3.Server(server_uri)
        user_dn = user_dn_template.format(username=username)
        try:
            conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            if conn.bind():
                user, created = User.objects.get_or_create(username=username)
                if created:
                    user.set_unusable_password()
                    user.save()
                return user
        except Exception as e:
            logging.warning(f"LDAP auth failed: {e}")
            return None
        return None
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class TACACSBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        tacacs_config = getattr(settings, 'TACACS_CONFIG', {})
        server = tacacs_config.get('SERVER')
        port = tacacs_config.get('PORT', 49)
        secret = tacacs_config.get('SECRET')
        if not (server and secret):
            return None
        try:
            cli = TACACSClient(server, port, secret, timeout=5, family=socket.AF_INET)
            authen = cli.authenticate(username, password)
            if authen.valid:
                user, created = User.objects.get_or_create(username=username)
                if created:
                    user.set_unusable_password()
                    user.save()
                return user
        except Exception as e:
            logging.warning(f"TACACS+ auth failed: {e}")
            return None
        return None
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class RADIUSBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        radius_config = getattr(settings, 'RADIUS_CONFIG', {})
        server = radius_config.get('SERVER')
        secret = radius_config.get('SECRET')
        port = radius_config.get('PORT', 1812)
        if not (server and secret):
            return None
        try:
            # Use a minimal dictionary for authentication
            radius_dict = Dictionary({})
            cli = RadiusClient(server=server, secret=secret.encode(), dict=radius_dict)
            req = cli.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username)
            req["User-Password"] = req.PwCrypt(password)
            reply = cli.SendPacket(req)
            if reply.code == pyrad.packet.AccessAccept:
                user, created = User.objects.get_or_create(username=username)
                if created:
                    user.set_unusable_password()
                    user.save()
                return user
        except Exception as e:
            logging.warning(f"RADIUS auth failed: {e}")
            return None
        return None
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None 