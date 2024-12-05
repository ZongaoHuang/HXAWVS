import os
import subprocess

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.shortcuts import HttpResponse
from django.contrib.auth.decorators import login_required
import json
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators import csrf
from webscan.utils import create_log_entry
from .models import Directoryscan
base_file_path = 'dirscan/dirsearch/reports/target.json'

@login_required
def dir_scan(request):
    """端口扫描"""
    scans = Directoryscan.objects.order_by('-scan_time')
    context = {
        'scans': scans
    }
    create_log_entry(request.user, '访问端口扫描页面')
    return render(request, 'dir-scan.html', context)
@login_required
def dir_scan_result(request, scan_id):
    """查看扫描结果"""
    scan = get_object_or_404(Directoryscan, id=scan_id)
    
    if os.path.exists(scan.result_path):
        with open(scan.result_path) as f:
            # 检查文件是否为空
            if os.stat(scan.result_path).st_size == 0:
                return render(request, "dir-result.html", {"error": "扫描结果为空"})

            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return render(request, "dir-result.html", {"error": "扫描结果格式错误"})

        # 处理数据
        k = set(data)
        k.discard('time')
        key_list = list(k)
        
        # 计数
        n = len(data)  # 使用len()函数简化计数
        # 列表合一
        a = []
        num = 0
        for key in data:
            num += 1
            if num < n:
                a += data[key]
        print({"a": a, "key_list": key_list})
                
        context = {
            'scan': scan,
            'a': a,
            'key_list': key_list
        }
        print(context)
        return render(request, "dir-result.html", context)
    else:
        return render(request, "dir-result.html", {"error": "暂无结果"})


@login_required
def dirresult(request):
    if os.access(base_file_path, os.F_OK):
        f = open(base_file_path)
        data = json.load(f)  # json被转换为python字典

        # 获取扫描url的端口等信息，将字典的键转为集合
        k = set(data)
        # 移除集合中的time
        # k.remove('time')
        # 安全移除time
        k.discard('time')
        # 键值集合转为列表
        key_list = list(k)

        # 计数
        n = 0
        for key in data:
            n = n + 1
        # 列表合一
        a = []
        num = 0
        for key in data:
            num = num + 1
            if num < n:
                a = a + data[key]
        print({"a": a, "key_list": key_list})
        return render(request, "dir-result.html", {"a": a, "key_list": key_list})
    else:
        error = "暂无结果"
        return render(request, "dir-result.html", {"error": error})


# -*- coding: utf-8 -*-



@login_required
def search_post(request):
    if request.POST:
        url = request.POST.get('url')
        
        # 创建扫描记录
        scan = Directoryscan.objects.create(
            user=request.user,
            target=url,
            status='process'
        )

        try:
            parm = []  # 勾选参数列表
            result_path = f'dirscan_results/dirscan_{scan.id}.json'  # 为每个扫描创建唯一的结果文件
            
            # 获取用户选择的参数，存入列表
            extensions = ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js']
            for ext in extensions:
                if request.POST.get(ext):
                    parm.append(request.POST.get(ext))

            # 构建扫描参数
            options = ' -e ' + ','.join(parm) if parm else ''
            recursive = '-r ' if request.POST.get('r_check') == "r_yes" else ''
            
            # 处理前缀
            prefixes = []
            pre_num = 1
            while request.POST.get(f'prefixe_{pre_num}'):
                prefixes.append(request.POST.get(f'prefixe_{pre_num}'))
                pre_num += 1
            prefix_opt = f'--prefixes {",".join(prefixes)} ' if prefixes else ''

            # 处理后缀
            suffixes = []
            suf_num = 1
            while request.POST.get(f'suffixe_{suf_num}'):
                suffixes.append(request.POST.get(f'suffixe_{suf_num}'))
                suf_num += 1
            suffix_opt = f'--suffixes {",".join(suffixes)} ' if suffixes else ''

            # 处理子目录
            subdirs = []
            s_num = 1
            while request.POST.get(f'subdirs_{s_num}'):
                subdirs.append(request.POST.get(f'subdirs_{s_num}'))
                s_num += 1
            subdir_opt = f'--subdirs {",".join(subdirs)} ' if subdirs else ''

            # 构建完整的扫描命令
            cmd = f'python dirscan/dirsearch/dirsearch.py -u {url} {options} {recursive} {prefix_opt} {suffix_opt} {subdir_opt} --json-report {result_path}'
            
            # 执行扫描
            process = subprocess.Popen(cmd, shell = True)
            process.communicate()

            # 更新扫描状态和结果路径
            scan.status = 'finish'
            scan.result_path = result_path
            scan.save()

            return JsonResponse({
                'code': 200,
                'data': {'scan_id': scan.id},
                'message': 'Scan completed successfully'
            })

        except Exception as e:
            scan.status = 'error'
            scan.save()
            return JsonResponse({
                'code': 500,
                'message': str(e)
            })

    return JsonResponse({
        'code': 400,
        'message': 'Invalid request'
    })




def get_target(request):
    try:
        file = open('reports/target.json', 'rb')
        response = HttpResponse(file)
        response['Content-Type'] = 'application/octet-stream'  # 设置头信息，告诉浏览器这是个文件
        response['Content-Disposition'] = 'attachment;filename="target.json"'
    except:
        response = HttpResponse("对不起，文件未生成")

    return response


@login_required
def get_dir_scans(request):
    """获取目录扫描列表"""
    scans = Directoryscan.objects.order_by('-scan_time')
    scan_list = []
    for scan in scans:
        scan_list.append({
            'id': scan.id,
            'user': scan.user.username,
            'target': scan.target,
            'scan_time': scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'result_path': scan.result_path
        })
    return JsonResponse({
        'code': 200,
        'data': scan_list
    })

@csrf_exempt
@login_required 
def delete_dir_scan(request):
    """删除扫描记录"""
    scan_id = request.POST.get('scan_id') 
    try:
        scan = Directoryscan.objects.get(id=scan_id, user=request.user)
        scan.delete()
        return JsonResponse({
            'code': 200,
            'data': {'success': True}
        })
    except Directoryscan.DoesNotExist:
        return JsonResponse({
            'code': 404,
            'message': 'Scan not found'
        })