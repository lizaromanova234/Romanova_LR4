from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('analytics/', views.analytics, name='analytics'),
    path('export/excel/', views.export_excel, name='export_excel'),
]