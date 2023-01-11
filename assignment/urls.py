
from django.contrib import admin
from django.urls import path,include
from assignment import views

urlpatterns = [
    path('items', views.ItemsView.as_view()),
    path('items/<int:id>', views.Item.as_view()),
    path('units', views.Units.as_view()),
]
