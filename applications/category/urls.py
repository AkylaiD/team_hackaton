from django.urls import path

from applications.category.views import CategoryListView

urlpatterns = [
    path('categories-list/', CategoryListView.as_view()),
]