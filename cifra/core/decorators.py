from django.contrib.auth.decorators import user_passes_test
import jwt
from django.http import JsonResponse,HttpResponseRedirect
from django.conf import settings
from functools import wraps
from datetime import datetime
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views import View

def role_required(role):
    """
    Decorator que verifica se o usuário autenticado possui a role informada.
    Exemplo de uso: @role_required("admin_ti")
    """
    def check_role(user):
        if not user.is_authenticated:
            return False
        if user.role == role:
            return True
        raise PermissionDenied  # retorna 403 se não tiver permissão
    return user_passes_test(check_role)