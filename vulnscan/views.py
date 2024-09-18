from tempfile import template

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from vulnscan.API.Scan import *
from vulnscan.API.Target import *
from vulnscan.API.Vuln import *
from vulnscan.API.Group import *
from vulnscan.API.Dashboard import *
from django.views.decorators.csrf import csrf_exempt
import json, re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from vulnscan.models import Middleware_vuln
from Sec_Tools.settings import API_KEY, API_URL
import time
from vulnscan.API.Report import Report
# Create your views here.
# API_URL = 'https://127.0.0.1:3443'
# API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936cc23a5d4737044dc18935d8a6f0199a50'

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .API.TargetOption import TargetOption


@csrf_exempt
@login_required
def delete_scan(request):
    s = Scan(API_URL, API_KEY)
    scan_id = request.POST.get('scan_id')
    status = s.delete(scan_id)
    if status:
        return success()
    return error()

@csrf_exempt
@login_required
def abort_scan(request):
    s = Scan(API_URL, API_KEY)
    scan_id = request.POST.get('scan_id')
    status = s.abort_scan(scan_id)
    if status:
        return success()
    return error()


@csrf_exempt
@login_required
def generate_report(request):
    r = Report(API_URL,API_KEY)
    template_id = "comprehensive"
    list_type = "scan_result"
    scan_session_id = request.POST.get('scan_session_id')
    id_list = [scan_session_id]
    status = r.generate(template_id, list_type, id_list)
    if status:
        return success()
    return error()

@login_required
def vulnscan(request):
    s = Scan(API_URL, API_KEY)
    data = s.get_all()
    count = 0
    s_list = []
    Middleware_datas = Middleware_vuln.objects.all()[::-1]
    for Middleware in Middleware_datas:
        # print(Middleware.url, Middleware.CVE_id, Middleware.result, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(Middleware.time))))
        result = 1 if Middleware.result=="True" else 0
        Middleware_data = {
            'id': count + 1,
            'status': Middleware.status,
            'target_id': None,
            'target': Middleware.url,
            'scan_type': Middleware.CVE_id,
            'vuln': {'high': result, 'medium': 0, 'low': 0, 'info': 0},
            'plan': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(Middleware.time)))
        }
        s_list.append(Middleware_data)
        count += 1
    for msg in data:
        table_data = {
            'id': count + 1,
            'status': msg['current_session']['status'],
            'target_id': msg['target_id'],
            'target': msg['target']['address'],
            'scan_type': msg["profile_name"],
            'vuln': msg['current_session']['severity_counts'],
            'plan': re.sub(r'T|\..*$', " ", msg['current_session']['start_date']),
            "scan_session_id":msg["current_session"]["scan_session_id"],
            "scan_id":msg["scan_id"]
        }
        s_list.append(table_data)
        count += 1
    data = s_list
    return render(request, "vulnscan.html", {"data": data })


@csrf_exempt
@login_required
def vuln_scan(request):
    t = Target(API_URL, API_KEY)
    s = Scan(API_URL, API_KEY)
    url = request.POST.get('ip')
    scan_type = request.POST.get('scan_type')
    username = request.POST.get('username')
    password = request.POST.get('password')
    cookie_header = request.POST.get('cookie_header')
    # print(cookie_header)

    # 先添加target目标
    target_id = t.add(url)
    if target_id:
        # 1. 设置账号密码
        if username and password:
            target_option = TargetOption(API_URL, API_KEY)
            login_success = target_option.set_site_login(target_id, 'automatic', {'username': username, 'password': password})
            if not login_success:
                return error()

        # 2. 设置cookie
        elif cookie_header:
            target_option = TargetOption(API_URL, API_KEY)
            login_success = target_option.set_cookie_login(target_id, cookie_header)
            if not login_success:
                return error()

        # 再添加scan扫描
        scan_id = s.add(target_id, scan_type)
        if scan_id:
            return success()
    return error()

@login_required
def vuln_result(request, target_id):
    d = Vuln(API_URL, API_KEY)
    data = []
    vuln_details = json.loads(d.search(None,None, "open", target_id=str(target_id)))

    id = 1
    for target in vuln_details['vulnerabilities']:
        item={
            'id': id,
            'severity': target['severity'],
            'target': target['affects_url'],
            'vuln_id':target['vuln_id'],
            'vuln_name': target['vt_name'],
            'time': re.sub(r'T|\..*$', " ", target['last_seen'])
        }
        id += 1
        data.append(item)
    return render(request,'vuln-reslut.html',{'data': data})

@login_required
def vuln_detail(request,vuln_id):
    d = Vuln(API_URL,API_KEY)
    data = d.get(vuln_id)
    print(data)
    parameter_list = BeautifulSoup(data['details'], features="html.parser").findAll('span')
    request_list = BeautifulSoup(data['details'], features="html.parser").findAll('li')
    data_dict = {
        'affects_url': data['affects_url'],
        'last_seen': re.sub(r'T|\..*$', " ", data['last_seen']),
        'vt_name': data['vt_name'],
        'details': data['details'].replace("  ",'').replace('</p>',''),
        'request': data['request'],
        'recommendation': data['recommendation'].replace('<br/>','\n'),
        'description': data['description'],
    }
    try:
        data_dict['parameter_name'] = parameter_list[0].contents[0]
        data_dict['parameter_data'] = parameter_list[1].contents[0]
    except:
        pass
    num = 1
    try:
        Str = ''
        for i in range(len(request_list)):
            Str += str(request_list[i].contents[0])+str(request_list[i].contents[1]).replace('<strong>', '').replace('</strong>', '')+'\n'
            num += 1
    except:
        pass
    data_dict['Tests_performed'] = Str
    data_dict['num'] = num
    data_dict['details'] = data_dict['details'].replace('class="bb-dark"','style="color: #ff0000"')
    return render(request, "vuln-detail.html", {'data': data_dict})


def test2(request):
    d = Vuln(API_URL,API_KEY)
    return HttpResponse(json.dumps(d.get('2495625645552306166')), content_type='application/json')

def get_target_id():
    s = Scan(API_URL, API_KEY)
    data = s.get_all()
    target_list = []
    for target in data:
        target_list.append(target['target_id'])
    return target_list


def get_vuln_id():
    d = Vuln(API_URL,API_KEY)
    data = d.get_all("open")
    vuln_list = []
    try:
        for vuln in data['vulnerabilities']:
           vuln_list.append(vuln['vuln_id'])
    except:
        pass
    return vuln_list


@csrf_exempt
@login_required
def get_vuln_rank(request):
    d = Dashboard(API_URL, API_KEY)
    data = json.loads(d.stats())["top_vulnerabilities"]
    vuln_rank = []
    for i in range(5):
        tem = {}
        tem['name'] = data[i]['name']
        tem['value'] = data[i]['count']
        vuln_rank.append(tem)
    return HttpResponse(json.dumps(vuln_rank), content_type='application/json')


@csrf_exempt
@login_required
def get_vuln_value(request):
    d = Dashboard(API_URL, API_KEY)
    # data = json.loads(d.stats())["vuln_count_by_criticality"]
    data = json.loads(d.stats())
    # print(data)
    result = {}
    # if data['high'] is not None:
    #     vuln_high_count = [i for i in data['high'].values()]
    #     result['high'] = vuln_high_count
    # if data['normal'] is not None:
    #     vuln_normal_count = data["normal"]
    #     result['normal'] = vuln_normal_count
    result["normal"] = data["vuln_count"]
    return HttpResponse(json.dumps(result), content_type='application/json')


Time = 0.0
@csrf_exempt
@login_required
def Middleware_scan(request):
    global Time
    try:
        url= request.POST.get('ip')
        CVE_id = request.POST.get('CVE_id').replace('-',"_")
        Time = time.time()  # time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))时间戳转日期格式
        if insert_Middleware_data(url, CVE_id, Time):
            return success()
    except:
        return error()

@csrf_exempt
@login_required
def start_Middleware_scan(request):
    try:
        url = request.POST.get('ip')
        ip, port = urlparse(url).netloc.split(':')
        CVE_id = request.POST.get('CVE_id').replace('-', "_")
        time.sleep(5) #等待数据插入成功后在查询出来扫描
        msg = Middleware_vuln.objects.filter(url=url, status='runing', CVE_id=CVE_id, time=Time)
        print(msg)
        for target in msg:
            result = POC_Check(target.url, target.CVE_id)
            # print("result:", result)
            update_Middleware_data(target.url, target.CVE_id, Time, result)
        return success()
    except:
        return error()


def insert_Middleware_data(url, CVE_id, Time, result=None, status="runing"):
    try:
        Middleware_vuln.objects.create(url=url, status=status, result=result, CVE_id=CVE_id, time=Time)
        print("insert success")
        return True
    except:
        print("data insert error")
        return False


def update_Middleware_data(url, CVE_id, Time, result):
    try:
        Middleware_vuln.objects.filter(url=url, status='runing', CVE_id=CVE_id, time=Time).update(status="completed", result=result)
        print("update success")
    except:
        print("data updata error")


def POC_Check(url, CVE_id):
    ip, port = urlparse(url).netloc.split(':')
    # Weblogic
    if CVE_id == "CVE_2020_2551":
        from vulnscan.POC.weblogic import cve_2020_2551_poc
        result = cve_2020_2551_poc.poc(url)
    elif CVE_id == "CVE_2018_2628":
        from vulnscan.POC.weblogic import cve_2018_2628_poc
        result = cve_2018_2628_poc.poc(ip, int(port), 0)
    elif CVE_id == "CVE_2018_2894":
        from vulnscan.POC.weblogic import cve_2018_2894_poc
        result = cve_2018_2894_poc.poc(url, "weblogic")
    #Drupal
    elif CVE_id == "CVE_2018_7600":
        from vulnscan.POC.Drupal import cve_2018_7600_poc
        result = cve_2018_7600_poc.poc(url)
    #Tomcat
    elif CVE_id == "CVE_2017_12615":
        from vulnscan.POC.tomcat import cve_2017_12615_poc
        result = cve_2017_12615_poc.poc(url)
    #jboss
    elif CVE_id == "CVE_2017_12149":
        from vulnscan.POC.jboss import cve_2017_12149_poc
        result = cve_2017_12149_poc.poc(url)
    #nexus
    elif CVE_id == "CVE_2020_10199":
        from vulnscan.POC.nexus import cve_2020_10199_poc
        result = cve_2020_10199_poc.poc(ip, port, "admin")
    #Struts2
    elif CVE_id == "Struts2_009":
        from vulnscan.POC.struts2 import struts2_009_poc
        result = struts2_009_poc.poc(url)
    elif CVE_id == "Struts2_032":
        from vulnscan.POC.struts2 import struts2_032_poc
        result = struts2_032_poc.poc(url)
    return result


def success(code=200, data=[], msg='success'):
    """
    返回成功的json数据
    :param code:
    :param data:
    :param msg:
    :return:
    """
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')


def error(code=400, data=[], msg='error'):
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')

