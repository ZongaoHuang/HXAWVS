# -*- coding =utf-8 -*-
# @Time:2021/2/3 13:04
# @Author:简简
# @File：urls.py
# @software:PyCharm


from django.urls import path
from webscan_backend import views

urlpatterns = [
    # 端口扫描
    path('port_scan', views.port_scan, name='port_scan'),
    path('port_scan_result/<int:scan_id>/', views.port_scan_result, name='port_scan_result'),
    path('get_port_scans', views.get_port_scans, name='get_port_scans'),
    path('delete_port_scan', views.delete_port_scan, name='delete_port_scan'),
    # 信息泄露
    path('info_leak', views.info_leak, name='info_leak'),
    path('info_leak_result/<int:scan_id>/', views.info_leak_result, name='info_leak_result'),
    path('get_info_leak', views.get_info_leak, name='get_info_leak'),
    path('delete_info_leak', views.delete_info_leak, name='delete_info_leak'),
    # 旁站扫描
    path('web_side', views.getwebsideinfo, name='web_side'),
    path('iplocating', views.iplocating, name='iplocating'),
    # 指纹识别
    path('whatcms', views.what_cms, name='whatcms'),
    path('iswaf', views.is_waf, name='iswaf'),
    path('isexistcdn', views.isexistcdn, name='cdncheck'),
    path('webweight', views.webweight, name='webweight'),
    path('baseinfo', views.baseinfo, name='baseinfo'),
    # 子域名探测
    path('_subdomain', views._subdomain, name='_subdomain'),
]
