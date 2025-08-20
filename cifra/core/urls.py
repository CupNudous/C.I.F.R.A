# core/urls.py
from django.urls import path
from core import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Home / dashboard
    path('', views.index, name='index'),

    # Autenticação (padrão do Django)
    path('login/', auth_views.LoginView.as_view(template_name='core/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='core/logout.html'), name='logout'),
    path('register/', views.register_view, name='register'),

    # Perfil
    path('profile/', views.profile_view, name='profile'),  # perfil do usuário logado
    path('profile/<str:username>/', views.profile_view, name='profile_public'),  # perfil público
    path('profile/edit/', views.profile_edit_view, name='profile_edit'),  # edição de perfil

    # Histórico e funcionalidades de treinamento
    path('attempts/', views.attempts_view, name='attempts'),  # histórico de tentativas
    path('training/', views.training_list, name='training'),  # lista de treinamentos
    path('training/<int:id>/submit/', views.simulation_view, name='training_submit'),  # submissão de simulação
    path('training/<int:id>/modal/', views.simulation_modal, name='simulation_modal'),  # modal da simulação
    path('training/<slug:module_slug>/<slug:lesson_slug>/', views.lesson_detail, name='lesson_detail'),  # detalhe de aula

    # Gamificação / comunidade
    path('ranking/', views.ranking_view, name='ranking'),
    path('achievements/', views.achievements_view, name='achievements'),

    # Relatórios
    path('reports/', views.reports_view, name='reports'),
    path('reports/<int:id>/', views.reports_view, name='report_detail'),

    # Informações e configurações
    path('about/', views.about_view, name='about'),
    path('settings/', views.settings_view, name='settings'),
]
