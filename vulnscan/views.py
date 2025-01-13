import gzip
import io
from tempfile import template

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.http import JsonResponse
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
from webscan.utils import create_log_entry
import requests

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import requests

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import requests
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC

import time

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from seleniumwire.utils import decode
@csrf_exempt
@login_required
def validate_login(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        print(f"Attempting to log in to URL: {url}")
        username = request.POST.get('username')
        print(f"Entered username: {request.POST.get('username')}")
        password = request.POST.get('password')
        print(f"Entered username: {request.POST.get('password')}")
        login_keyword_list = ["登录","login", "denglu", "pass", "mima", "admin"]
        # 设置 Chrome 选项
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("disable_encoding")
        seleniumwire_options = {
            'disable_encoding': True  # Ask the server not to compress the response
        }
        # 启动 Chrome 浏览器
        driver = webdriver.Chrome(service=Service(), options=chrome_options, seleniumwire_options=seleniumwire_options)

        try:
            # 打开登录页面
            print("Opening the login page...")
            driver.get(url)
            
            # 等待页面加载
            time.sleep(5)
            print("Page loaded, searching for input fields...")

            # 直接查找页面中的所有输入框
            input_fields = driver.find_elements(By.XPATH, '//input')
            if len(input_fields) < 2:
                print("Error: Less than 2 input fields found.")
                return HttpResponse('Unable to find enough input fields', status=400)

            # 尝试使用 input0 和 input1
            try:
                username_input = input_fields[0]  # 第一个输入框
                password_input = input_fields[1]  # 第二个输入框
                print(f"username:{username_input}")
                print(f"password: {password_input}")
                # 尝试查找登录按钮或表单
                login_button = None
                for keyword in login_keyword_list:
                    try:
                        # 尝试查找按钮（使用更简单的 XPath）
                        print(f"1.1: Found login button with value: {keyword}")
                        login_button = driver.find_element(By.XPATH, f'//button[contains(@value, {keyword})]')
                        break
                    except NoSuchElementException:
                        try:
                            # 尝试查找输入框
                            print(f"1.2: Found login button with value: {keyword}.")
                            login_button = driver.find_element(By.XPATH, f'//span[contains(@value, {keyword})]')
                            break
                        except NoSuchElementException:
                            try:
                                # 尝试查找按钮文本
                                login_button = driver.find_element(By.XPATH, f'//button[contains(text(), {keyword})]')
                                print(f"1.3 Found login button using simplified XPath.")
                                break
                            except NoSuchElementException:
                                continue

                # 输入用户名和密码
                username_input.clear()
                username_input.send_keys(username)
                username = username_input.get_attribute('value')
                print(f"username:{username}")
                password_input.clear()
                password_input.send_keys(password)
                password = password_input.get_attribute('value')
                print(f"password:{password}")
                # 提交方式
                all_responses = []
                # 提交方式
                if login_button:
                    # 如果找到登录按钮，点击按钮
                    webdriver.ActionChains(driver).move_to_element(login_button).click(login_button).perform()
                    print(f"2.4 login_button.")                
                    for request in driver.requests:
                        if 'login' in request.url:
                            if request.response:
                                print(
                                    request.url,
                                    request.response.status_code,
                                    request.response.headers['Content-Encoding'],
                                    request.response.headers['Content-Type'],
                                    request.response.body.decode('utf-8', errors='replace') 
                                )
                                if request.response.headers['Content-Encoding']=='gzip':
                                    decompressed_data = gzip.decompress(request.response.body)
                                    print(decompressed_data.decode('utf-8', errors='replace') )
                                    
                                response_content = {
                                'url': request.url,
                                'status_code': request.response.status_code,
                                'Content-Encoding': request.response.headers['Content-Encoding'],
                                'content_type': request.response.headers['Content-Type'],
                                'body_len': len(request.response.body)
                                }
                                all_responses.append(response_content)

                        

                else:
                    # 如果没有找到登录按钮，使用表单提交
                    password_input.submit()
                    print(f"2.5 password_input.")
                    for request in driver.requests:
                        if 'login' in request.url:
                            if request.response:
                                print(
                                    request.url,
                                    request.response.status_code,
                                    request.response.headers['Content-Encoding'],
                                    request.response.headers['Content-Type'],
                                    request.response.body.decode('utf-8', errors='replace') 
                                )
                                if request.response.headers['Content-Encoding']=='gzip':
                                    decompressed_data = gzip.decompress(request.response.body)
                                    print(decompressed_data.decode('utf-8', errors='replace') )
                                    
                                response_content = {
                                'url': request.url,
                                'status_code': request.response.status_code,
                                'Content-Encoding': request.response.headers['Content-Encoding'],
                                'content_type': request.response.headers['Content-Type'],
                                'body_len': len(request.response.body)
                                }
                                all_responses.append(response_content)


                # 等待页面加载
                time.sleep(3)
                print("Waiting for the response...")
                # 返回响应内容
                return JsonResponse({'code': 200, 'data': all_responses}, safe=False)  # 返回JSON格式的响应

            except Exception as e:
                print(f"Error with input0 and input1: {str(e)}")
                print("Trying input1 and input2...")

                # 尝试使用 input1 和 input2
                if len(input_fields) < 3:
                    print("Error: Less than 3 input fields found.")
                    return HttpResponse('Unable to find enough input fields', status=400)

                username_input = input_fields[1]  # 第二个输入框
                password_input = input_fields[2]  # 第三个输入框
                print(f"username:{username_input}")
                print(f"password: {password_input}")

                # 尝试查找登录按钮或表单
                login_button = None
                for keyword in login_keyword_list:
                    try:
                        # 尝试查找按钮（使用更简单的 XPath）
                        print(f"2.1: Found login button with value: {keyword}")
                        login_button = driver.find_element(By.XPATH, f'//button[contains(@value, {keyword})]')
                        break
                    except NoSuchElementException:
                        try:
                            # 尝试查找输入框
                            print(f"2.2: Found login button with value: {keyword}.")
                            login_button = driver.find_element(By.XPATH, f'//span[contains(@value, {keyword})]')
                            break
                        except NoSuchElementException:
                            try:
                                # 尝试查找按钮文本
                                login_button = driver.find_element(By.XPATH, f'//button[contains(text(), {keyword})]')
                                print(f"2.3 Found login button using simplified XPath.")
                                break
                            except NoSuchElementException:
                                continue

                username_input.clear()
                username_input.send_keys(username)
                username = username_input.get_attribute('value')
                print(f"username:{username}")
                password_input.clear()
                password_input.send_keys(password)
                password = password_input.get_attribute('value')
                print(f"password:{password}")
                all_responses = []
                # 提交方式
                if login_button:
                    # 如果找到登录按钮，点击按钮
                    webdriver.ActionChains(driver).move_to_element(login_button).click(login_button).perform()
                    print(f"2.4 login_button.")                
                    for request in driver.requests:
                        if 'login' in request.url:
                            if request.response:
                                print(
                                    request.url,
                                    request.response.status_code,
                                    request.response.headers['Content-Encoding'],
                                    request.response.headers['Content-Type'],
                                    request.response.body.decode('utf-8', errors='replace') 
                                )
                                if request.response.headers['Content-Encoding']=='gzip':
                                    decompressed_data = gzip.decompress(request.response.body)
                                    print(decompressed_data.decode('utf-8', errors='replace') )
                                    
                                response_content = {
                                'url': request.url,
                                'status_code': request.response.status_code,
                                'Content-Encoding': request.response.headers['Content-Encoding'],
                                'content_type': request.response.headers['Content-Type'],
                                'body_len': len(request.response.body)
                                }
                                all_responses.append(response_content)

                        

                else:
                    # 如果没有找到登录按钮，使用表单提交
                    password_input.submit()
                    print(f"2.5 password_input.")
                    for request in driver.requests:
                        if 'login' in request.url:
                            if request.response:
                                print(
                                    request.url,
                                    request.response.status_code,
                                    request.response.headers['Content-Encoding'],
                                    request.response.headers['Content-Type'],
                                    request.response.body.decode('utf-8', errors='replace') 
                                )
                                if request.response.headers['Content-Encoding']=='gzip':
                                    decompressed_data = gzip.decompress(request.response.body)
                                    print(decompressed_data.decode('utf-8', errors='replace') )
                                    
                                response_content = {
                                'url': request.url,
                                'status_code': request.response.status_code,
                                'Content-Encoding': request.response.headers['Content-Encoding'],
                                'content_type': request.response.headers['Content-Type'],
                                'body_len': len(request.response.body)
                                }
                                all_responses.append(response_content)

                        

                # 等待页面加载
                time.sleep(3)
                print("All responses")
                # 返回响应内容
                return JsonResponse({'code': 200, 'data': all_responses}, safe=False)  # 返回JSON格式的响应
            
        except Exception as e:
            print(f'Error: {str(e)}')  # 打印错误信息到控制台
            return JsonResponse({'code': 500, 'message': str(e)}, status=500)

        finally:
            # driver.quit()  # 关闭浏览器
            print("Browser closed.")

    return JsonResponse({'code': 400, 'message': 'Invalid request method'}, status=400)


@csrf_exempt
@login_required
def validate_header(request):
    if request.method == 'POST':
        header_value = request.POST.get('header')  # 假设这里是前端填入的 header
        url = request.POST.get('url')
        
        # 发送请求到指定的 URL 进行 Header 验证
        try:
            # 判断 header 的类型并构建请求头
            headers = {}
            if header_value.startswith('Cookie:'):
                headers['Cookie'] = header_value[len('Cookie:'):].strip()  # 去掉前缀并清理空格
            elif header_value.startswith('Authorization:'):
                headers['Authorization'] = header_value[len('Authorization:'):].strip()  # 去掉前缀并清理空格
            
            # 添加 User-Agent
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
            
            # 发送 GET 请求
            response = requests.get(url, headers=headers)

            # 直接返回响应的内容
            return HttpResponse(response.content, content_type=response.headers.get('Content-Type'), status=response.status_code)

        except requests.exceptions.RequestException as e:
            # 捕获请求相关的异常
            return HttpResponse(f'Error: {str(e)}', status=500)

    return HttpResponse('Invalid request method', status=400)


@csrf_exempt
@login_required
def delete_scan(request):
    s = Scan(API_URL, API_KEY)
    scan_id = request.POST.get('scan_id')
    status = s.delete(scan_id)
    if status:
        create_log_entry(request.user, '删除漏洞扫描任务')
        return success()
    return error()

@csrf_exempt
@login_required
def abort_scan(request):
    s = Scan(API_URL, API_KEY)
    scan_id = request.POST.get('scan_id')
    status = s.abort_scan(scan_id)
    if status:
        create_log_entry(request.user, '中止漏洞扫描任务')
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
        create_log_entry(request.user, '生成报告')
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
            'user': request.user.username, 
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
            'user': request.user.username,
            'status': msg['current_session']['status'],
            'target_id': msg['target_id'],
            'target': msg['target']['address'],
            'description': msg['target']['description'],
            'scan_type': msg["profile_name"],
            'vuln': msg['current_session']['severity_counts'],
            'plan': re.sub(r'T|\..*$', " ", msg['current_session']['start_date']),
            "scan_session_id":msg["current_session"]["scan_session_id"],
            "scan_id":msg["scan_id"]
        }
        s_list.append(table_data)
        count += 1
        print(msg['current_session']['severity_counts'])
    data = s_list
    create_log_entry(request.user, '访问漏洞扫描页面')
    return render(request, "vulnscan.html", {"data": data })

@csrf_exempt
@login_required
def get_vuln_scans(request):
    try:
        s = Scan(API_URL, API_KEY)
        data = s.get_all()
        count = 0
        s_list = []
        
        # 获取中间件数据
        Middleware_datas = Middleware_vuln.objects.all()[::-1]
        for Middleware in Middleware_datas:
            result = 1 if Middleware.result=="True" else 0
            Middleware_data = {
                'id': count + 1,
                # 'user': request.user.username,
                'status': Middleware.status,
                'target_id': None,
                'target': Middleware.url,
                'scan_type': Middleware.CVE_id,
                'vuln': {'critical': result, 'high': 0, 'medium': 0, 'low': 0},
                'plan': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(Middleware.time)))
            }
            s_list.append(Middleware_data)
            count += 1

        # 获取扫描数据
        for msg in data:
            scan_data = {
                'id': count + 1,
                # 'user': request.user.username,
                'status': msg['current_session']['status'],
                'target_id': msg['target_id'],
                'target': msg['target']['address'],
                'description': msg['target']['description'],
                'scan_type': msg["profile_name"],
                'vuln': msg['current_session']['severity_counts'],
                'plan': re.sub(r'T|\..*$', " ", msg['current_session']['start_date']),
                "scan_session_id":msg["current_session"]["scan_session_id"],
                "scan_id":msg["scan_id"]
            }
            s_list.append(scan_data)
            count += 1
            
        return JsonResponse({
            'code': 200,
            'data': s_list,
            'message': 'success'
        })
    except Exception as e:
        return JsonResponse({
            'code': 500,
            'message': str(e)
        })

@csrf_exempt
@login_required
def vuln_scan(request):
    t = Target(API_URL, API_KEY)
    s = Scan(API_URL, API_KEY)
    url = request.POST.get('ip')
    description = request.POST.get('description')
    scan_type = request.POST.get('scan_type')
    username = request.POST.get('username')
    password = request.POST.get('password')
    cookie_header = request.POST.get('cookie_header')
    # print(cookie_header)

    # 先添加target目标
    target_id = t.add(url, description)
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
            create_log_entry(request.user, '进行漏洞扫描任务')
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
    create_log_entry(request.user, '查看漏洞扫描结果')
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
    create_log_entry(request.user, '查看漏洞扫描详情页面')
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
        create_log_entry(request.user, '进行中间件扫描任务')
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

