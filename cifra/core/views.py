# core/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, get_user_model
from django.contrib import messages
from django.http import JsonResponse
from django.db import transaction
from datetime import datetime, timedelta
from django.conf import settings
import jwt
import bleach

from .models import Simulation, Attempt, Campaign, Module, Lesson, Achievement
from .forms import CustomUserCreationForm, ProfileForm
from .serializers import SimulationSerializer, AttemptSerializer, AchievementSerializer
from rest_framework import viewsets, permissions, mixins, status
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from .utils import evaluate_response, apply_score
from core.decorators import role_required

# ---------- Configurações JWT ----------
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
SESSION_EXPIRE_HOURS = 1  # horas

def create_session_token(user_id):
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=SESSION_EXPIRE_HOURS),
        "type": "session"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

User = get_user_model()

# ---------- Sanitização HTML ----------
ALLOWED_TAGS = ['p','br','strong','em','ul','ol','li','h1','h2','h3','h4','pre','code','blockquote','a','img','table','thead','tbody','tr','th','td']
ALLOWED_ATTRS = {
    '*': ['class', 'style'],
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'width', 'height'],
    'td': ['colspan', 'rowspan']
}

# ---------- Permissões ----------
def is_admin_ti(user):
    return user.is_authenticated and user.role == "admin_ti"

class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)

# ---------- API ViewSets ----------
class SimulationViewSet(viewsets.ModelViewSet):
    queryset = Simulation.objects.all().order_by('-created_at')
    serializer_class = SimulationSerializer
    permission_classes = [IsAdminOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class AttemptViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin):
    queryset = Attempt.objects.select_related('user', 'simulation').all()
    serializer_class = AttemptSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return super().get_queryset()
        return self.queryset.filter(user=user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        attempt = serializer.save()
        return Response(self.get_serializer(attempt).data, status=status.HTTP_201_CREATED)

class AchievementViewSet(viewsets.ModelViewSet):
    queryset = Achievement.objects.select_related('user').all()
    serializer_class = AchievementSerializer
    permission_classes = [IsAdminUser]

class LeaderboardView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, format=None):
        limit = int(request.query_params.get('limit', 10))
        users = User.objects.all().order_by('-score')[:limit]
        data = [{"id": u.id, "username": u.username, "first_name": u.first_name, "last_name": u.last_name, "score": u.score} for u in users]
        return Response(data)

# ---------- Views de autenticação ----------
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user:
            auth_login(request, user)
            # Token de sessão opcional
            session_token = create_session_token(user.id)
            response = redirect('index')
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=False,
                secure=False,
                samesite='Lax',
                path='/',
                max_age=SESSION_EXPIRE_HOURS*3600
            )
            return response
        else:
            messages.error(request, "Usuário ou senha inválidos.")
    return render(request, 'core/login.html')

def logout_view(request):
    auth_logout(request)
    return redirect('login')

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = form.cleaned_data.get('role', 'employee')
            user.save()
            auth_login(request, user)
            return redirect('index')
    else:
        form = CustomUserCreationForm()
    return render(request, 'core/register.html', {'form': form})

# ---------- Views principais ----------
@login_required
def index(request):
    return render(request, 'core/index.html')

@login_required
def profile_view(request, username=None):
    user_obj = get_object_or_404(User, username=username) if username else request.user
    template = 'core/profile_public.html' if username else 'core/profile.html'
    return render(request, template, {'user_obj': user_obj})

@login_required
def profile_edit_view(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('profile')
    else:
        form = ProfileForm(instance=request.user)
    return render(request, 'core/profile_edit.html', {'form': form})

# ---------- Treinamento ----------
@login_required
def training_list(request):
    modules = Module.objects.prefetch_related('lessons').order_by('order', 'title')
    simulations = Simulation.objects.all().order_by('-created_at')[:50]
    return render(request, 'core/training.html', {'modules': modules, 'simulations': simulations})

@login_required
def lesson_detail(request, module_slug, lesson_slug):
    module = get_object_or_404(Module, slug=module_slug)
    lesson = get_object_or_404(Lesson, module=module, slug=lesson_slug)
    safe_html = bleach.clean(lesson.content_html or '', tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'title': lesson.title, 'content_html': safe_html})
    return render(request, 'core/lesson_detail.html', {'module': module, 'lesson': lesson, 'content_html': safe_html})

# ---------- Campanhas e Simulações ----------
@login_required
def campaign_list_view(request):
    campaigns = Campaign.objects.filter(is_active=True)
    return render(request, 'core/campaign_list.html', {'campaigns': campaigns})

@login_required
def campaign_detail_view(request, campaign_id):
    campaign = get_object_or_404(Campaign, id=campaign_id, is_active=True)
    simulations = campaign.simulations.all()
    return render(request, 'core/campaign_detail.html', {'campaign': campaign, 'simulations': simulations})

@login_required
def simulation_view(request, simulation_id):
    """
    Exibe uma simulação (question, email, site) e registra tentativas.
    """
    simulation = get_object_or_404(Simulation, id=simulation_id)

    # --- Registro automático de emails/sites se POST não enviado ---
    if simulation.type in ['email', 'site'] and request.method == 'GET':
        # Considera que visualizar ou clicar é uma tentativa
        Attempt.objects.get_or_create(
            user=request.user,
            simulation=simulation,
            defaults={
                'response_choice': 'viewed',
                'is_correct': False,
                'score_delta': 0,
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:300]
            }
        )

    # --- Submissão de resposta (questões ou interações) ---
    if request.method == 'POST':
        response_choice = request.POST.get('choice') or request.POST.get('response_choice') or ''

        is_correct, score_delta = evaluate_response(simulation, response_choice)

        ip_addr = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:300]

        with transaction.atomic():
            Attempt.objects.create(
                user=request.user,
                simulation=simulation,
                response_choice=response_choice,
                is_correct=is_correct,
                score_delta=score_delta,
                ip_address=ip_addr,
                user_agent=user_agent
            )
            apply_score(request.user, score_delta)

        if simulation.type == 'question':
            if is_correct:
                messages.success(request, f"Resposta correta! +{score_delta} pontos")
            else:
                messages.error(request, f"Resposta incorreta. {score_delta} pontos")
        elif simulation.type in ['email', 'site']:
            messages.info(request, f"Tentativa registrada para {simulation.type}.")

        return redirect('training_detail', id=simulation.id)

    # --- Renderização do template ---
    template_map = {
        'question': 'core/simulation_question.html',
        'email': 'core/simulation_email.html',
        'site': 'core/simulation_site.html'
    }
    template = template_map.get(simulation.type, 'core/simulation_question.html')

    return render(request, template, {'simulation': simulation})

def simulation_modal(request, id):
    simulation = get_object_or_404(Simulation, id=id)
    return render(request, 'core/simulation_modal.html', {'simulation': simulation})

# ---------- Outras páginas ----------
def about_view(request):
    return render(request, 'core/about.html')

@login_required
@role_required("admin_ti")
def reports_view(request, id=None):
    template = 'core/report_detail.html' if id else 'core/reports.html'
    return render(request, template, {'report_id': id})

def settings_view(request):
    return render(request, 'core/settings.html')

@login_required
def attempts_view(request):
    return render(request, 'core/attempts.html')

def ranking_view(request):
    return render(request, 'core/ranking.html')

def achievements_view(request):
    return render(request, 'core/achievements.html')
