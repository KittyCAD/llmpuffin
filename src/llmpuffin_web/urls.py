from django.contrib import admin
from django.urls import path

from llmpuffin_web import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.runs_list),
    path("checkpoints/", views.checkpoints_list),
    path("checkpoints/<str:thread_id>/", views.checkpoint_detail),
    path("checkpoints/<str:thread_id>/resume/", views.checkpoint_resume),
    path("runs/<int:run_id>/", views.run_detail),
    path("runs/<int:run_id>/delete/", views.run_delete),
    path("runs/<int:run_id>/resume/<str:thread_id>/", views.run_resume),
    path("runs/<int:run_id>/fork/<str:thread_id>/", views.run_fork),
    path("findings/<int:finding_id>/", views.finding_detail),
    path("findings/<int:finding_id>/fork/", views.finding_fork),
    path("store/", views.store_list),
    path("store/<path:prefix>/", views.store_namespace),
    path("profiles/", views.profiles_list),
    path("profiles/create/", views.profile_create),
    path("profiles/<int:profile_id>/", views.profile_detail),
    path("profiles/<int:profile_id>/run/", views.profile_run),
]
