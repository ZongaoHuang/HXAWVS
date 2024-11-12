import os

import pytz

from django.http import JsonResponse
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.contrib.auth.decorators import login_required
import json
from webscan.utils import create_log_entry
from .models import DirectoryScan
from django.views.decorators.csrf import csrf_exempt

base_file_path = 'dirscan/dirsearch/reports/target.json'

@login_required
def dirresult(request, scan_id):
    try:
        scan = DirectoryScan.objects.get(id=scan_id, user=request.user)
        if scan.result_path and os.path.exists(scan.result_path):
            with open(scan.result_path, 'r') as f:
                data = json.load(f)
            
            results = []
            for url, details in data.items():
                if url != 'time':
                    for item in details:
                        results.append({
                            'path': item['path'],
                            'status': item['status'],
                            'content_length': item['content-length'],
                            'redirect': item.get('redirect', '')
                        })
            
            create_log_entry(request.user, f'查看目录识别结果: {scan.target}')
            return render(request, "dir-result.html", {"a": results, "scan": scan, "key_list": [scan.target]})
        else:
            error = "扫描结果未找到"
            return render(request, "dir-result.html", {"error": error, "scan": scan})
    except DirectoryScan.DoesNotExist:
        error = "扫描记录未找到"
        return render(request, "dir-result.html", {"error": error})

@login_required
def dir_scan(request):
    scans = DirectoryScan.objects.filter(user=request.user).order_by('-scan_time')
    context = {
        'scans': [
            {
                'id': scan.id,
                'target': scan.target,
                'status': scan.status,
                'scan_time': scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                'result_path': scan.result_path,
            }
            for scan in scans
        ]
    }
    return render(request, "dir-scan.html", context)

@csrf_exempt
@login_required
def abort_dirscan(request):
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        try:
            scan = DirectoryScan.objects.get(id=scan_id, user=request.user)
            if scan.status == 'process':
                scan.status = 'aborted'
                scan.save()
                create_log_entry(request.user, '中止目录扫描任务')
                return JsonResponse({'code': 200, 'message': 'Scan aborted successfully'})
            else:
                return JsonResponse({'code': 400, 'message': 'Scan is not in progress'})
        except DirectoryScan.DoesNotExist:
            return JsonResponse({'code': 404, 'message': 'Scan not found'})
    return JsonResponse({'code': 405, 'message': 'Method not allowed'})

@csrf_exempt
@login_required
def delete_dirscan(request):
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        try:
            scan = DirectoryScan.objects.get(id=scan_id, user=request.user)
            scan.delete()
            create_log_entry(request.user, '删除目录扫描任务')
            return JsonResponse({'code': 200, 'message': 'Scan deleted successfully'})
        except DirectoryScan.DoesNotExist:
            return JsonResponse({'code': 404, 'message': 'Scan not found'})
    return JsonResponse({'code': 405, 'message': 'Method not allowed'})

