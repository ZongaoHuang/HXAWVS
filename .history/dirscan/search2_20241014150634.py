# -*- coding: utf-8 -*-
import os

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
    context = {}
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            new_scan = DirectoryScan.objects.create(
                user=request.user,
                target=url,
                status='process'
            )
            create_log_entry(request.user, f'开始目录扫描任务: {url}')

            # 获取用户选择的参数，存入列表
            extensions = ','.join([ext for ext in ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js'] if request.POST.get(ext)])

            # 递归扫描
            recursive = '-r' if request.POST.get('r_check') == "r_yes" else ''

            # 前缀
            prefixes = ','.join([request.POST.get(f'prefixe_{i}') for i in range(1, 10) if request.POST.get(f'prefixe_{i}')])
            pre = f'--prefixes {prefixes}' if prefixes else ''

            # 后缀
            suffixes = ','.join([request.POST.get(f'suffixe_{i}') for i in range(1, 10) if request.POST.get(f'suffixe_{i}')])
            suf = f'--suffixes {suffixes}' if suffixes else ''

            # 指定子目录扫描
            subdirs = ','.join([request.POST.get(f'subdirs_{i}') for i in range(1, 10) if request.POST.get(f'subdirs_{i}')])
            subdir = f'--subdirs {subdirs}' if subdirs else ''

            # Prepare the output file path
            output_file = f'dirscan/dirsearch/reports/{new_scan.id}.json'
            new_scan.result_path = output_file
            new_scan.save()

            # Construct the dirsearch command
            command = f'python dirscan/dirsearch/dirsearch.py -u {url}'
            if extensions:
                command += f' -e {extensions}'
            command += f' {recursive} {pre} {suf} {subdir} --json-report -o {output_file}'

            # Execute the dirsearch command
            import subprocess
            process = subprocess.Popen(command, shell=True)

            # Update the scan object with the process ID
            new_scan.pid = process.pid
            new_scan.save()

            context['scan_id'] = new_scan.id
            context['message'] = '扫描已开始'
        else:
            context['error'] = 'URL is required'

    return render(request, "dir-scan.html", context)