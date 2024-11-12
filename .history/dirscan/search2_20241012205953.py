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
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            new_scan = DirectoryScan.objects.create(
                user=request.user,
                target=url,
                status='process'
            )
            create_log_entry(request.user, f'开始目录扫描任务: {url}')

            # Prepare parameters for dirsearch
            parm = []
            options = ''
            for ext in ['php', 'asp', 'jsp', 'txt', 'zip', 'html', 'js']:
                if request.POST.get(ext):
                    parm.append(ext)
            if parm:
                options = ' -e ' + ','.join(parm)

            recursive = ' -r' if request.POST.get('r_check') == "r_yes" else ''

            prefixes = ','.join([request.POST.get(f'prefixe_{i}') for i in range(1, 10) if request.POST.get(f'prefixe_{i}')])
            if prefixes:
                prefixes = f' --prefixes {prefixes}'

            suffixes = ','.join([request.POST.get(f'suffixe_{i}') for i in range(1, 10) if request.POST.get(f'suffixe_{i}')])
            if suffixes:
                suffixes = f' --suffixes {suffixes}'

            subdirs = ','.join([request.POST.get(f'subdirs_{i}') for i in range(1, 10) if request.POST.get(f'subdirs_{i}')])
            if subdirs:
                subdirs = f' --subdirs {subdirs}'

            # Prepare the output file path
            output_file = f'dirscan/dirsearch/reports/{new_scan.id}.json'

            # Construct the dirsearch command
            command = f'python dirscan/dirsearch/dirsearch.py -u {url}{options}{recursive}{prefixes}{suffixes}{subdirs} --format=json -o {output_file}'

            # Execute the dirsearch command
            import subprocess
            process = subprocess.Popen(command, shell=True)

            # Update the scan object with the process ID
            new_scan.pid = process.pid
            new_scan.save()

            return JsonResponse({'status': 'success', 'scan_id': new_scan.id})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})
