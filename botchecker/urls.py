# БЛОК 1: ИМПОРТ БИБЛИОТЕК
from django.urls import path      # Функция path для определения маршрутов URL
from . import views               # Импорт представлений (views.py) из текущего приложения

# БЛОК 2: МАРШРУТИЗАЦИЯ URL (СПИСОК МАРШРУТОВ)
urlpatterns = [
    # Маршрут для главной страницы (пустая строка)
    # При переходе на /botchecker/ вызывается функция index() из views.py
    path('', views.index, name='index'),

    # Маршрут для страницы "О проекте"
    # При переходе на /botchecker/about/ вызывается функция about() из views.py
    path('about/', views.about, name='about'),

    # Маршрут для страницы аналитики
    # При переходе на /botchecker/analytics/ вызывается функция analytics() из views.py
    path('analytics/', views.analytics, name='analytics'),

    # Маршрут для экспорта данных в Excel
    # При переходе на /botchecker/export/excel/ вызывается функция export_excel() из views.py
    path('export/excel/', views.export_excel, name='export_excel'),
]