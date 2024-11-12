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
# 接收POST请求数据
@login_required
def search_post(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            new_scan = DirectoryScan.objects.create(
                user=request.user,
                target=url,
                status='process'
            )
            create_log_entry(request.user, f'开始目录扫描任务: {url}')

            extensions = ','.join([ext for ext in ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js'] if request.POST.get(ext)])
            recursive = '-r' if request.POST.get('r_check') == "r_yes" else ''
            prefixes = ','.join([request.POST.get(f'prefixe_{i}') for i in range(1, 10) if request.POST.get(f'prefixe_{i}')])
            pre = f'--prefixes {prefixes}' if prefixes else ''
            suffixes = ','.join([request.POST.get(f'suffixe_{i}') for i in range(1, 10) if request.POST.get(f'suffixe_{i}')])
            suf = f'--suffixes {suffixes}' if suffixes else ''
            subdirs = ','.join([request.POST.get(f'subdirs_{i}') for i in range(1, 10) if request.POST.get(f'subdirs_{i}')])
            subdir = f'--subdirs {subdirs}' if subdirs else ''

            output_file = f'dirscan/dirsearch/reports/{new_scan.id}.json'
            new_scan.result_path = output_file
            new_scan.save()

            command = f'python dirscan/dirsearch/dirsearch.py -u {url}'
            if extensions:
                command += f' -e {extensions}'
            command += f' {recursive} {pre} {suf} {subdir} --json-report {output_file}'

            import subprocess
            process = subprocess.Popen(command, shell=True)

            new_scan.pid = process.pid
            new_scan.save()

            return JsonResponse({'status': 'success', 'scan_id': new_scan.id, 'message': '扫描已开始'})
        else:
            return JsonResponse({'status': 'error', 'message': 'URL is required'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})