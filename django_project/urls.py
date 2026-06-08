"""
URL configuration for django_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# БЛОК 1: ИМПОРТ БИБЛИОТЕК
from django.contrib import admin          # Административная панель Django
from django.urls import path, include     # Маршрутизация: path и include для подключения приложений
from tasks import views                   # Представления приложения tasks (шаблон)

# БЛОК 2: МАРШРУТИЗАЦИЯ (СПИСОК URL-ПАТТЕРНОВ)
urlpatterns = [
    # Маршрут для административной панели
    # При переходе на /admin/ открывается панель управления Django
    path("admin/", admin.site.urls),

    # Маршрут для корневой страницы (путь "/")
    # При переходе на главную страницу вызывается функция views.index из приложения tasks
    # Это заглушка / шаблон, созданный при инициализации проекта
    path("", views.index),

    # Маршрут для приложения botchecker
    # Все URL, начинающиеся с /botchecker/, передаются в файл urls.py приложения botchecker
    # include() подключает маршруты из botchecker/urls.py
    path("botchecker/", include("botchecker.urls")),
]
