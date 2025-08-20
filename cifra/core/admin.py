from django.contrib import admin
from .models import Simulation, Attempt, Achievement, User
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import Module, Lesson

@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    pass

admin.site.register(Simulation)
admin.site.register(Attempt)
admin.site.register(Achievement)

class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 0

@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ('title', 'order')
    inlines = [LessonInline]

@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ('title', 'module', 'order', 'created_at')
    list_filter = ('module',)
    search_fields = ('title', 'module__title')