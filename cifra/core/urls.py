from django.urls import path
from core import views
from django.contrib.auth import views as auth_views
from django.http import HttpResponse

urlpatterns = [
    path('', views.index, name='index'),  # página inicial
    path('login/', auth_views.LoginView.as_view(template_name='core/login.html'), name='login'), #login
    path('logout/', auth_views.LogoutView.as_view(template_name='core/logout.html'), name='logout'), #logout
    path('register/', views.register_view, name='register'), #cadastro
    path('attempts/', views.attempts_view, name='attempts'), #histórico de tentativas e resoluções
    path('profile/', views.profile_view, name='profile'), #perfil
    path('profile/<str:username>/', views.profile_view, name='profile'), #perfil específico de usuário por id
    path('profile/edit/', views.profile_edit_view, name='profile_edit'), #editar perfil
    path('ranking/', views.ranking_view, name='ranking'), #ranking
    path('achievements/', views.achievements_view, name='achievements'), #conquistas
    path('training/', views.training_view, name='training'),
    #path('<int:id>/training/', views.training_detail, name='training_detail'),
    #path('training/submit/<int:id>/', views.submit_attempt, name='submit_attempt'),
    path('about/', views.about_view, name='about'), #sobre o sistema
    path('reports/', views.reports_view, name='reports'), #relatórios
    path('reports/<int:id>/', views.reports_view, name='reports'), #relatórios específicos por id
    path('settings/', views.settings_view, name='settings'), #configurações
]
