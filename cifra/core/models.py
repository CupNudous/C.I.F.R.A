# core/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings


class User(AbstractUser):
    ROLE_EMPLOYEE = "employee"
    ROLE_ADMIN_TI = "admin_ti"

    ROLE_CHOICES = [
        (ROLE_EMPLOYEE, "Funcionário"),
        (ROLE_ADMIN_TI, "Admin TI"),
    ]

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ROLE_EMPLOYEE,
    )

    score = models.IntegerField(default=0)

    def save(self, *args, **kwargs):
        """
        Ajusta automaticamente a role se for superusuário.
        Caso contrário, respeita o valor já definido.
        """
        if self.is_superuser:
            self.role = self.ROLE_ADMIN_TI
        super().save(*args, **kwargs)

    def __str__(self):
        return self.get_full_name() or self.username

    @property
    def is_employee(self):
        return self.role == self.ROLE_EMPLOYEE

    @property
    def is_admin_ti(self):
        return self.role == self.ROLE_ADMIN_TI

class Simulation(models.Model):
    """
    Simulação base: email phishing, site falso, questionário, etc.
    """
    TYPE_EMAIL = "email"
    TYPE_SITE = "site"
    TYPE_QUESTION = "question"
    TYPE_CHOICES = [
        (TYPE_EMAIL, "Email"),
        (TYPE_SITE, "Site"),
        (TYPE_QUESTION, "Questionário"),
    ]

    DIFFICULTY_EASY = "easy"
    DIFFICULTY_MEDIUM = "medium"
    DIFFICULTY_HARD = "hard"
    DIFFICULTY_CHOICES = [
        (DIFFICULTY_EASY, "Fácil"),
        (DIFFICULTY_MEDIUM, "Médio"),
        (DIFFICULTY_HARD, "Difícil"),
    ]

    title = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    type = models.CharField(max_length=15, choices=TYPE_CHOICES, default=TYPE_EMAIL)
    subject = models.CharField(max_length=200, blank=True)  # útil para emails
    body = models.TextField(blank=True)  # corpo do email / descrição do caso
    choices = models.JSONField(blank=True, null=True,
                               help_text="Opções apresentadas ao usuário (se aplicável).")
    correct_choice = models.CharField(max_length=200, blank=True,
                                      help_text="Identificador da opção correta (ex.: 'opcao_a' ou texto).")
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES, default=DIFFICULTY_MEDIUM)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        try:
            type_display = self.get_type_display()
        except Exception:
            type_display = self.type
        return f"{self.title} ({type_display})"


class Campaign(models.Model):
    """
    Campanha que agrupa várias simulações (emails, sites, questionários).
    """
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    simulations = models.ManyToManyField(Simulation, related_name='campaigns')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Attempt(models.Model):
    """
    Registro de tentativa do usuário para uma Simulation.
    Guarda a escolha do usuário, se estava correta, delta de pontos e metadados.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="attempts")
    simulation = models.ForeignKey(Simulation, on_delete=models.CASCADE, related_name="attempts")
    response_choice = models.CharField(max_length=200, blank=True)
    is_correct = models.BooleanField(default=False)
    score_delta = models.IntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.user} - {self.simulation} - {'Correct' if self.is_correct else 'Wrong'}"

    class Meta:
        ordering = ["-timestamp"]

class Achievement(models.Model):
    """
    Conquistas que podem ser atribuídas a usuários.
    Podem ser criadas manualmente ou por lógica (signals).
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="achievements")
    code = models.CharField(max_length=100, blank=True, help_text="Código único da conquista (ex: FIRST_WIN).")
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    date_awarded = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-date_awarded"]

    def __str__(self):
        return f"{self.name} - {self.user}"


# --------------------------
# Novos modelos para conteúdos
# --------------------------
class Module(models.Model):
    """
    Representa um módulo de aprendizado (ex.: 'LGPD', 'Segurança da Informação', ...).
    Cada módulo contém várias lessons/lessons.
    """
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True, max_length=200)
    summary = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order', 'title']
        verbose_name = "Módulo"
        verbose_name_plural = "Módulos"

    def __str__(self):
        return self.title


class Lesson(models.Model):
    """
    Unidade de conteúdo dentro de um Module. O conteúdo principal é armazenado em HTML
    (content_html) para facilitar a renderização no frontend.
    """
    module = models.ForeignKey(Module, on_delete=models.CASCADE, related_name='lessons')
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200)
    content_html = models.TextField(blank=True, help_text="HTML sanitizado para renderizar a lição")
    content_markdown = models.TextField(blank=True, help_text="(Opcional) versão em markdown")
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    resources_file = models.FileField(upload_to='lesson_resources/', null=True, blank=True,
                                      help_text="Arquivo (PDF/DOCX) disponível para download")

    class Meta:
        unique_together = ('module', 'slug')
        ordering = ['order']
        verbose_name = "Lição"
        verbose_name_plural = "Lições"

    def __str__(self):
        return f"{self.module.title} - {self.title}"
