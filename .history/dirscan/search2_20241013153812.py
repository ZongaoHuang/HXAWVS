# -*- coding: utf-8 -*-
import os

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators import csrf
from django.contrib.auth.decorators import login_required
from webscan.utils import create_log_entry
from .models import DirectoryScan
if not os.path.exists('./dirscan/dirsearch/logs'):
    os.mkdir('./dirscan/dirsearch/logs')


# 接收POST请求数据
@login_required
def search_post(request):
    parm = []  # 勾选参数列表
    base_file_path = 'dirscan/dirsearch/reports/target.json'  # json文件地址
    fixes = {}
    if request.POST:
        url = request.POST.get('url')
        if url:
            new_scan = DirectoryScan.objects.create(
                user=request.user,
                target=url,
                status='process'
            )
            create_log_entry(request.user, f'开始目录扫描任务: {url}')

            # 获取用户选择的参数，存入列表
            parm = [request.POST.get(ext) for ext in ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js'] if request.POST.get(ext)]
            options = ' -e ' + ','.join(parm) if parm else ''

            # 递归扫描
            recursive = ' -r' if request.POST.get('r_check') == "r_yes" else ''

            # 前缀
            prefixes = ','.join([request.POST.get(f'prefixe_{i}') for i in range(1, 10) if request.POST.get(f'prefixe_{i}')])
            pre = f' --prefixes {prefixes}' if prefixes else ''

            # 后缀
            suffixes = ','.join([request.POST.get(f'suffixe_{i}') for i in range(1, 10) if request.POST.get(f'suffixe_{i}')])
            suf = f' --suffixes {suffixes}' if suffixes else ''

            # 指定子目录扫描
            subdirs = ','.join([request.POST.get(f'subdirs_{i}') for i in range(1, 10) if request.POST.get(f'subdirs_{i}')])
            subdir = f' --subdirs {subdirs}' if subdirs else ''

            # Prepare the output file path
            output_file = f'dirscan/dirsearch/reports/{new_scan.id}.json'
            new_scan.result_path = output_file
            new_scan.save()

            # Construct the dirsearch command
            command = f'python dirscan/dirsearch/dirsearch.py -u {url}{options}{recursive}{pre}{suf}{subdir} --format=json -o {output_file}'

            # Execute the dirsearch command
            import subprocess
            process = subprocess.Popen(command, shell=True)

            # Update the scan object with the process ID
            new_scan.pid = process.pid
            new_scan.save()
            return JsonResponse({'status': 'success', 'scan_id': new_scan.id})

    return render(request, "dir-scan.html", fixes)