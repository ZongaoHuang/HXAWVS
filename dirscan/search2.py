# -*- coding: utf-8 -*-
import os

from django.http import JsonResponse
import subprocess
from django.db import transaction
from django.shortcuts import render
from django.views.decorators import csrf
from django.contrib.auth.decorators import login_required
from webscan.utils import create_log_entry
from .models import DirectoryScan
if not os.path.exists('./dirscan/dirsearch/logs'):
    os.mkdir('./dirscan/dirsearch/logs')


# 接收POST请求数据


@login_required
def dir_create(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            new_scan = DirectoryScan.objects.create(
                user=request.user,
                target=url,
                status='process'
            )
            create_log_entry(request.user, f'创建目录扫描任务: {url}')
            return JsonResponse({'status': 'success', 'scan_id': new_scan.id, 'target': url})
        else:
            return JsonResponse({'status': 'error', 'message': 'URL is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def dir_search(request):
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        try:
            scan = DirectoryScan.objects.get(id=scan_id, user=request.user)
            create_log_entry(request.user, f'开始目录扫描任务: {scan.target}')

            # Get user-selected parameters
            extensions = ','.join([ext for ext in ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js'] if request.POST.get(ext)])
            recursive = '-r' if request.POST.get('r_check') == "r_yes" else ''
            prefixes = ','.join([request.POST.get(f'prefixe_{i}') for i in range(1, 10) if request.POST.get(f'prefixe_{i}')])
            pre = f'--prefixes {prefixes}' if prefixes else ''
            suffixes = ','.join([request.POST.get(f'suffixe_{i}') for i in range(1, 10) if request.POST.get(f'suffixe_{i}')])
            suf = f'--suffixes {suffixes}' if suffixes else ''
            subdirs = ','.join([request.POST.get(f'subdirs_{i}') for i in range(1, 10) if request.POST.get(f'subdirs_{i}')])
            subdir = f'--subdirs {subdirs}' if subdirs else ''

            output_file = f'dirscan/dirsearch/reports/{scan.id}.json'
            scan.result_path = output_file
            scan.save()

            command = f'python dirscan/dirsearch/dirsearch.py -u {scan.target}'
            if extensions:
                command += f' -e {extensions}'
            command += f' {recursive} {pre} {suf} {subdir} --json-report {output_file}'
            print(command)
            process = subprocess.Popen(command, shell=True)
            scan.pid = process.pid
            scan.save()

            # Wait for the process to complete
            process.wait()

            # Update scan status to 'finish' when the process is complete
            scan.status = 'finish'
            scan.save()
            return JsonResponse({'status': 'success', 'scan_id': scan.id, 'message': '扫描完成'})
        except DirectoryScan.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Scan not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
