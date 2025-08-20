# cifra/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from core.views import (
    SimulationViewSet,
    AttemptViewSet,
    AchievementViewSet,
    LeaderboardView,
)

router = routers.DefaultRouter()
router.register(r'simulations', SimulationViewSet, basename='simulation')
router.register(r'attempts', AttemptViewSet, basename='attempt')
router.register(r'achievements', AchievementViewSet, basename='achievement')

urlpatterns = [
    path('admin/', admin.site.urls),

    # API (DRF router) -- ficará acessível sob /api/
    path('api/', include(router.urls)),

    # Endpoints adicionais
    path('api/leaderboard/', LeaderboardView.as_view(), name='leaderboard'),

    # JWT (obter token / refresh)
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Opcional: login na browsable API do DRF
    path('api/auth/', include('rest_framework.urls')),

    # Rotas das páginas/templates do app core
    path('', include('core.urls')),
]
