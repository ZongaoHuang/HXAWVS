import json
import os
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
# Create your views here.

# -*- coding:utf-8 -*-
from django.views.decorators.csrf import csrf_exempt
from .plugins.common.common import success, error, addslashes, getdomain, getdomainip, check_ip, check_url
import time
from .plugins.common.common import getuserip
from .plugins.loginfo.loginfo import LogHandler
from .models import PortScan, InfoLeak
MYLOGGER = LogHandler(time.strftime("%Y-%m-%d", time.localtime()) + 'log')


@csrf_exempt  # 标识一个视图可以被跨域访问
@login_required  # 用户登陆系统才可以访问
def port_scan(request):
    """
    获取开放端口列表
    """
    from .plugins.portscan.portscan import ScanPort
    ip = request.POST.get('ip')
    if check_ip(ip):
        scan = PortScan.objects.create(
            user=request.user,
            target=ip,
            status='process'
        )
        result = ScanPort(ip).pool()
        
        # Save the result to a file
        result_path = f'port_scan_results/port_scan_{scan.id}.json'
        os.makedirs(os.path.dirname(result_path), exist_ok=True)
        with open(result_path, 'w') as f:
            json.dump(result, f)
        
        scan.result_path = result_path
        scan.status = 'finish'
        scan.save()
        
        MYLOGGER.info(
            'M:' + request.method + ' P:' + request.path + ' UPOST:' + str(request.POST) + ' SC:200 UIP:' + getuserip(
                request) + ' RDATA:' + str(result))
        return success(200, result, 'ok!')
    return error(400, '请填写正确的IP地址', 'error')
@csrf_exempt 
@login_required
def port_scan_result(request, scan_id):
    scan = get_object_or_404(PortScan, id=scan_id, user=request.user)
    with open(scan.result_path, 'r') as f:
        result = json.load(f)
    return render(request, 'scan/port_scan_result.html', {'scan': scan, 'result': result})

@csrf_exempt
@login_required
def get_port_scans(request):
    scans = PortScan.objects.filter(user=request.user).order_by('-scan_time')
    scan_data = []
    for scan in scans:
        scan_data.append({
            'id': scan.id,
            'target': scan.target,
            'scan_time': scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'result_path': scan.result_path
        })
    return success(200, scan_data, 'ok')

@csrf_exempt
@login_required
def delete_port_scan(request):
    scan_id = request.POST.get('scan_id')
    try:
        scan = PortScan.objects.get(id=scan_id, user=request.user)
        if scan.result_path:
            if os.path.exists(scan.result_path):
                os.remove(scan.result_path)
        scan.delete()
        return success(200, {'success': True}, 'Scan deleted successfully')
    except PortScan.DoesNotExist:
        return error(404, {'success': False}, 'Scan not found')

@csrf_exempt
@login_required
def info_leak(request):
    """
    信息泄漏检测
    """
    from .plugins.infoleak.infoleak import get_infoleak
    url = check_url(request.POST.get('url'))
    if url:
        scan = InfoLeak.objects.create(
            user=request.user,
            target=url,
            status='process'
        )
        result = get_infoleak(url)
        
        # Save the result to a file
        result_path = f'info_leak_results/info_leak_{scan.id}.json'
        os.makedirs(os.path.dirname(result_path), exist_ok=True)
        with open(result_path, 'w') as f:
            json.dump(result, f)
        
        scan.result_path = result_path
        scan.status = 'finish'
        scan.save()
        
        MYLOGGER.info(
            'M:' + request.method + ' P:' + request.path + ' UPOST:' + str(request.POST) + ' SC:200 UIP:' + getuserip(
                request) + ' RDATA:' + str(result))
        return success(200, {'scan_id': scan.id}, 'ok')
    return error(400, '请填写正确的URL地址', 'error')

@csrf_exempt
@login_required
def info_leak_result(request, scan_id):
    scan = get_object_or_404(InfoLeak, id=scan_id, user=request.user)
    with open(scan.result_path, 'r') as f:
        result = json.load(f)
    return render(request, 'scan/info_leak_result.html', {'scan': scan, 'result': result})

@csrf_exempt
@login_required
def get_info_leak(request):
    scans = InfoLeak.objects.filter(user=request.user).order_by('-scan_time')
    scan_data = []
    for scan in scans:
        scan_data.append({
            'id': scan.id,
            'target': scan.target,
            'scan_time': scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'result_path': scan.result_path
        })
    return success(200, scan_data, 'ok')

@csrf_exempt
@login_required
def delete_info_leak(request):
    scan_id = request.POST.get('scan_id')
    try:
        scan = InfoLeak.objects.get(id=scan_id, user=request.user)
        if scan.result_path:
            if os.path.exists(scan.result_path):
                os.remove(scan.result_path)
        scan.delete()
        return success(200, {'success': True}, 'Scan deleted successfully')
    except InfoLeak.DoesNotExist:
        return error(404, {'success': False}, 'Scan not found')
   




@csrf_exempt
def getwebsideinfo(request):
    """
    获取旁站信息
    """
    from .plugins.webside.webside import get_side_info
    ip = request.POST.get('ip')
    if check_ip(ip):
        result = get_side_info(ip)
        if result:
            return success(200, result, 'ok')
        return error(400, '未找到旁站信息！', 'error')
    return error(400, '请填写正确的IP地址', 'error')


@csrf_exempt
def baseinfo(request):
    """
    返回网站的基本信息接口
    """
    from .plugins.baseinfo.baseinfo import getbaseinfo
    url = check_url(request.POST.get('url'))
    if url:
        res = getbaseinfo(url)
        MYLOGGER.info(
            'M:' + request.method + ' P:' + request.path + ' UPOST:' + str(request.POST) + ' SC:200 UIP:' + getuserip(
                request) + ' RDATA:' + str(res))
        return success(res['code'], res, res['msg'])
    return error(400, '请填写正确的URL地址', '请输入正确的网址， 例如：http://example.cn')


@csrf_exempt
def webweight(request):
    """
    获取网站权重
    """
    from .plugins.webweight.webweight import get_web_weight
    url = check_url(request.POST.get('url'))
    if url:
        result = get_web_weight(url)
        MYLOGGER.info('M:' + request.method + ' P:' + request.path + ' UPOST:' + str(
            request.POST) + ' SC:200 UIP:' + getuserip(request) + ' RDATA:' + str(result))
        return success(200, result, 'ok')
    return error(400, '请填写正确的URL地址', 'error')


@csrf_exempt
def iplocating(request):
    """
    ip定位
    """
    from .plugins.iplocating.iplocating import get_locating
    ip = request.POST.get('ip')
    if check_ip(ip):
        result = get_locating(ip)
        return success(200, result, 'ok')
    return error(400, '请填写正确的IP地址', 'error')


@csrf_exempt
def isexistcdn(request):
    """
    判断当前域名是否使用了CDN
    """
    from .plugins.cdnexist.cdnexist import iscdn
    url = check_url(request.POST.get('url'))
    if url:
        result_str = iscdn(url)
        if result_str == '目标站点不可访问':
            return success(200, result_str, '网络错误')
        if result_str:
            result_str = '存在CDN（源IP可能不正确）'
        else:
            result_str = '无CDN'
        return success(200, result_str, 'Success!')
    return error(400, '请填写正确的IP地址', 'error')


@csrf_exempt
def is_waf(request):
    """
    判断当前域名是否使用了WAF
    """
    from .plugins.waf.waf import getwaf
    url = check_url(request.POST.get('url'))
    if url:
        return success(200, getwaf(url), 'ok')
    return error(400, '请填写正确的URL地址', 'error')


@csrf_exempt
def what_cms(request):
    """
    判断当前域名使用了什么框架，cms等指纹信息
    """
    from .plugins.whatcms.whatcms import getwhatcms
    url = check_url(request.POST.get('url'))
    if url:
        result = getwhatcms(url)
        MYLOGGER.info('M:' + request.method + ' P:' + request.path + ' UPOST:' + str(
            request.POST) + ' SC:200 UIP:' + getuserip(request) + ' RDATA:' + str(result))
        return success(200, result, 'ok')
    return error(400, '请填写正确的URL地址', 'error')


@csrf_exempt
@login_required
def finger_print_result(request, scan_id):
    scan = get_object_or_404(InfoLeak, id=scan_id, user=request.user)
    with open(scan.result_path, 'r') as f:
        result = json.load(f)
    return render(request, 'scan/info_leak_result.html', {'scan': scan, 'result': result})

@csrf_exempt
@login_required
def get_finger_print(request):
    scans = InfoLeak.objects.filter(user=request.user).order_by('-scan_time')
    scan_data = []
    for scan in scans:
        scan_data.append({
            'id': scan.id,
            'target': scan.target,
            'scan_time': scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'result_path': scan.result_path
        })
    return success(200, scan_data, 'ok')

@csrf_exempt
@login_required
def delete_finger_print(request):



@csrf_exempt
def _subdomain(request):
    '''子域名扫描'''
    from .plugins.subdomain.subdomain import get_subdomain
    domain = request.POST.get('domain')
    print(domain)
    if domain:
        result = get_subdomain(domain)
        print(len(result))
        MYLOGGER.info(
            'M:' + request.method + ' P:' + request.path + ' UPOST:' + str(request.POST) + ' SC:200 UIP:' + getuserip(
                request) + ' RDATA:' + str(result))
        return success(200, result, 'ok')
    return error(400, '请填写正确的URL地址', 'error')
