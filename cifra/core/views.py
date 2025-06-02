from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .forms import ProfileForm
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm
from django.contrib.auth import authenticate, login
from django.contrib import messages
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
""
@login_required
def index(request):
    return render(request, 'core/index.html')

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    return Response({'message': f'Olá, {request.user.username}! Você está autenticado.'})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')  # ou outra página após login
        else:
            messages.error(request, "Usuário ou senha inválidos.")
    return render(request, 'core/login.html')  # redireciona para página inicial

def logout_view(request):
    return HttpResponse("Logout - Em construção")

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('index')
    else:
        form = CustomUserCreationForm()
    return render(request, 'core/register.html', {'form': form})

def attempts_view(request):
    return HttpResponse("Histórico de tentativas - Em construção")

def profile_view(request, username=None):
    if username:
        return HttpResponse(f"Perfil público de {username} - Em construção")
    return HttpResponse("Perfil do usuário logado - Em construção")

def profile_edit_view(request):
    return HttpResponse("Editar Perfil - Em construção")

def ranking_view(request):
    return HttpResponse("Ranking - Em construção")

def achievements_view(request):
    return HttpResponse("Conquistas - Em construção")

def training_view(request, id=None):
    if id:
        return HttpResponse(f"Treinamento {id} - Em construção")
    return HttpResponse("Lista de treinamentos - Em construção")

def about_view(request):
    return HttpResponse("Sobre o sistema - Em construção")

def reports_view(request, id=None):
    if id:
        return HttpResponse(f"Relatório {id} - Em construção")
    return HttpResponse("Lista de relatórios - Em construção")

def settings_view(request):
    return HttpResponse("Configurações - Em construção")

"""

@login_required
def profile_view(request):
    user = request.user
    return render(request, 'core/profile.html', {'user': user})

def profile_public_view(request, username):
    user = get_object_or_404(User, username=username)
    public_data = {
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
    }
    return render(request, 'core/profile_public.html', {'user_data': public_data})

@login_required
def profile_edit_view(request):
    user = request.user

    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect('profile')  # verifique se a url name está correta
    else:
        form = ProfileForm(instance=user)

    return render(request, 'core/profile_edit.html', {'form': form})
"""
