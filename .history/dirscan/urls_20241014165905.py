from django.contrib import admin
from django.urls import path
from . import views
from dirscan import views, search2, target

urlpatterns = [
    path('dir-result/', views.dirresult, name="dir-result"),
    path('dir-scan/', views.dir_scan, name="dir-scan"),
    path('dir-search/', search2.search_post, name="dir-search"),
    path('get-target/', target.get_target, name="get-target"),
    path('abort_dirscan/', views.abort_dirscan, name="abort_dirscan"),
    path('delete_dirscan/', views.delete_dirscan, name="delete_dirscan")
]