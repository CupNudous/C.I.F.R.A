from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class User(AbstractUser):
    score = models.IntegerField(default=0)

    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',  # altere para evitar conflito
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
        related_query_name='user',
    )

    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
        related_query_name='user',
    )

class Simulation(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    # outros campos importantes, como tipo, dificuldade, data de criação

    def __str__(self):
        return self.title

class Attempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    simulation = models.ForeignKey(Simulation, on_delete=models.CASCADE)
    is_correct = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)

class Achievement(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField()
    date_awarded = models.DateTimeField(auto_now_add=True)

