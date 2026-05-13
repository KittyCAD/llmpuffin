from django.contrib import admin
from django.urls import path

from llmpuffin_web import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.checkpoints_list),
    path("checkpoints/<str:thread_id>/", views.checkpoint_detail),
    path("profiles/", views.profiles_list),
    path("profiles/create/", views.profile_create),
    path("profiles/<int:profile_id>/", views.profile_detail),
    path("profiles/<int:profile_id>/run/", views.profile_run),
]
