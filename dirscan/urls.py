from django.contrib import admin
from django.urls import path
from . import views
from dirscan import views

urlpatterns = [
    path('dir-result/', views.dirresult, name="dir-result"),
    path('dir-search/', views.search_post, name="dir-search"),
    path('get-target/', views.get_target, name="get-target"),
    path('dir-scan/', views.dir_scan, name="dir-scan"),
    path('get_dir_scans/', views.get_dir_scans, name='get_dir_scans'),
    path('delete_dir_scan/', views.delete_dir_scan, name='delete_dir_scan'),
    path('dir-scan-result/<int:scan_id>/', views.dir_scan_result, name='dir_scan_result'),
]
