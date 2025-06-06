from .forms import DirectoryScanForm
from .forms import URLReputationForm
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.contrib import messages
from .forms import FileUploadForm, CustomRegistrationForm, DirectoryScanForm
from .forms import EmailAuthenticationForm
from .models import UploadedFile, SuspiciousActivity, ScannedURL
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm
import requests
import time
import os
import json
from django.contrib.auth import authenticate
from django.utils.timesince import timesince
from django.urls import reverse
import tempfile
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from .forms import UserForm, ProfileForm
from django.http import JsonResponse

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')


def login(request):
    if request.method == 'POST':
        form = EmailAuthenticationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user:
                auth_login(request, user)
                return redirect('dashboard')
    else:
        form = EmailAuthenticationForm()
    return render(request, 'home.html', {'form': form, 'active_tab': 'signin'})


def user_logout(request):
    auth_logout(request)
    return redirect("profile")


def home(request):
    if request.method == 'POST':
        form = EmailAuthenticationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user:
                auth_login(request, user)
                return redirect('profile')  # Change to your desired redirect
    else:
        form = EmailAuthenticationForm()
    return render(request, 'home.html', {'form': form, 'active_tab': 'signin'})


def register(request):
    if request.method == "POST":
        form = CustomRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")
    else:
        form = CustomRegistrationForm()
    return render(request, 'home.html', {'form': form, 'active_tab': 'signup'})


def success(request):
    return render(request, 'success.html')


@login_required
def profile(request):
    user = request.user
    profile = user.profile
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=user)
        profile_form = ProfileForm(
            request.POST, request.FILES, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
            return redirect('dashboard')
        else:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': user_form.errors})
    else:
        user_form = UserForm(instance=user)
        profile_form = ProfileForm(instance=profile)
    return render(request, 'profile.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'user': user,
    })


@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user  # Set the user here!
            uploaded_file.save()
            return redirect('dashboard')  # or wherever you want
    else:
        form = FileUploadForm()
    return render(request, 'upload_file.html', {'form': form})


@login_required
def check_integrity(request, file_id):
    uploaded_file = get_object_or_404(
        UploadedFile, id=file_id, user=request.user)
    hash_md5 = hashlib.md5()
    with open(uploaded_file.file.path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    file_checksum = hash_md5.hexdigest()
    if file_checksum != uploaded_file.checksum:
        uploaded_file.status = 'MODIFIED'
        uploaded_file.save()
        SuspiciousActivity.objects.create(
            user=request.user,
            event_type='INTEGRITY_CHECK_FAILURE',
            details=f"Integrity check failed for file: {uploaded_file.file.name}",
            timestamp=timezone.now()
        )
        messages.error(
            request, "File integrity check failed. The file has been modified.")
    else:
        uploaded_file.status = 'INTEGRITY_CHECK_PASSED'
        uploaded_file.save()
        messages.success(
            request, "File integrity check passed. The file is intact.")
    return redirect('profile')


@login_required
def check_malware(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(id=file_id, user=request.user)
    except UploadedFile.DoesNotExist:
        messages.error(request, "File not found.")
        return redirect('profile')
    virustotal_api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': uploaded_file.checksum}
    response = requests.get(virustotal_api_url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        # Save scan results
        uploaded_file.scan_positives = json_response.get('positives')
        uploaded_file.scan_total = json_response.get('total')
        uploaded_file.scan_result = json.dumps(json_response)
        uploaded_file.scan_date = timezone.now()
        # Save VirusTotal permalink if present
        uploaded_file.scan_report_url = json_response.get('permalink')
        uploaded_file.save()
        # ...existing status logic...
        if json_response.get('positives', 0) > 0:
            uploaded_file.status = 'INFECTED'
            SuspiciousActivity.objects.create(
                user=request.user,
                event_type='MALWARE_DETECTION',
                details=f"Malware detected in file: {uploaded_file.file.name}",
                timestamp=timezone.now()
            )
        else:
            uploaded_file.status = 'CLEAN'
        uploaded_file.save()
        messages.success(request, "Malware scan completed.")
    else:
        messages.error(request, "Failed to scan file with VirusTotal.")
    return redirect('profile')


def poll_virustotal_scan(scan_id):
    virustotal_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
    while True:
        response = requests.get(virustotal_url, params=params)
        if response.status_code == 200:
            json_response = response.json()
            response_code = json_response.get('response_code')
            if response_code == 1:
                scan_date = json_response.get('scan_date')
                positives = json_response.get('positives')
                if scan_date is not None and positives is not None:
                    return json_response
                if response_code == -2:
                    time.sleep(10)
                else:
                    return None
            else:
                return None
        else:
            return None


@login_required
def check_url_reputation(request):
    result = None
    error_message = None

    if request.method == 'POST':
        form = URLReputationForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            virustotal_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
            response = requests.post(virustotal_url, params=params)
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get('response_code') == 1:
                    scan_id = json_response.get('scan_id')
                    scan_results = poll_virustotal_scan(scan_id)
                    if scan_results:
                        positives = scan_results.get('positives', 0)
                        total = scan_results.get('total', 0)
                        if positives > 0:
                            result = {
                                "status": "danger",
                                "message": f"⚠️ This URL is flagged by {positives} out of {total} engines."
                            }
                            status = "inactive"
                        else:
                            result = {
                                "status": "success",
                                "message": "✅ This URL is clean according to VirusTotal."
                            }
                            status = "active"
                        # Save to DB
                        ScannedURL.objects.create(
                            user=request.user,
                            url=url,
                            status=status
                        )
                    else:
                        result = {
                            "status": "warning",
                            "message": "Could not retrieve scan results. Please try again."
                        }
                else:
                    result = {
                        "status": "warning",
                        "message": "Error with URL submission to VirusTotal."
                    }
            else:
                result = {
                    "status": "danger",
                    "message": "Failed to submit URL for scanning."
                }
        else:
            error_message = "Please enter a valid URL."
    else:
        form = URLReputationForm()

    # Fetch all scanned URLs for this user, most recent first
    links = ScannedURL.objects.filter(user=request.user).order_by('-date')

    # Pass links to template for table rendering
    return render(request, 'check_url_reputation.html', {
        'form': form,
        'result': result,
        'error_message': error_message,
        'links': [
            {
                "id": link.id,
                "short_url": link.url,
                "status": link.status,
                "date": link.date.strftime("%b - %d -%Y")
            }
            for link in links
        ]
    })


def execute_scan_for_malware(request):
    if request.method == 'POST':
        form = DirectoryScanForm(request.POST)
        if form.is_valid():
            directory_path = form.cleaned_data['directory_path']
            files = [os.path.join(directory_path, filename) for filename in os.listdir(
                directory_path) if os.path.isfile(os.path.join(directory_path, filename))]
            if not files:
                message = "No files found in the specified directory."
                scan_results = []
            else:
                malware_found = False
                scan_results = []
                for file in files:
                    try:
                        virustotal_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
                        params = {'apikey': VIRUSTOTAL_API_KEY}
                        files = {
                            'file': (os.path.basename(file), open(file, 'rb'))}
                        response = requests.post(
                            virustotal_url, params=params, files=files)
                        if response.status_code == 200:
                            json_response = response.json()
                            if json_response.get('response_code') == 1:
                                scan_id = json_response.get('scan_id')
                                scan_results.append({
                                    'file_name': os.path.basename(file),
                                    'scan_id': scan_id,
                                })
                                scan_details = poll_virustotal_scan(scan_id)
                                if scan_details and scan_details.get('positives', 0) > 0:
                                    malware_found = True
                                    scanned_file = os.path.basename(file)
                                else:
                                    message = "Error with file submission to VirusTotal."
                            else:
                                message = "Failed to submit file for scanning."
                    except Exception as e:
                        message = f"Error during file submission: {str(e)}"
                if malware_found:
                    SuspiciousActivity.objects.create(
                        user=request.user,
                        event_type='MALWARE_DETECTION',
                        details=f"Malware detected in files within the directory: {directory_path}",
                        timestamp=timezone.now()
                    )
                if scan_results:
                    message = "Malware scan completed successfully."
                else:
                    message = "No files found for scanning."
        else:
            message = "Invalid input. Please provide a valid directory path."
            scan_results = []
    else:
        form = DirectoryScanForm()
        message = ""
        scan_results = []
    infected_files = [result['file_name']
                      for result in scan_results if result.get('positives', 0) > 0]
    return render(request, 'execute_scan_for_malware.html', {
        'form': form,
        'message': message,
        'scanned_file': scanned_file if 'scanned_file' in locals() else None,
        'scan_results': scan_results,
        'infected_files': infected_files,
    })


@login_required
def scan_reports(request, scan_id):
    scan = get_object_or_404(UploadedFile, id=scan_id, user=request.user)
    positives = scan.scan_positives or 0
    total_engines = scan.scan_total or 1  # Avoid division by zero
    stroke_dashoffset = 377 - \
        (positives / total_engines) * 377 if total_engines else 377

    # Parse engines from scan_result JSON
    engines = []
    try:
        result = json.loads(scan.scan_result) if scan.scan_result else {}
        scans = result.get("scans", {})
        for engine_name, data in scans.items():
            engines.append({
                "name": engine_name,
                "status": "detected" if data.get("detected") else "undetected",
                "result": data.get("result", ""),
            })
    except Exception:
        pass

    context = {
        "file_name": scan.file.name.split('/')[-1] if scan.file and scan.file.name else scan.file_name,
        "uploaded_at": scan.uploaded_at,
        "checksum": scan.checksum,
        "file_size": scan.file.size if scan.file and scan.file.name else 0,
        "last_scanned": scan.scan_date,
        "positives": positives,
        "total_engines": scan.scan_total or 0,
        "stroke_dashoffset": stroke_dashoffset,
        "rescan_url": reverse('rescan_file', args=[scan.id]),
        "virustotal_url": scan.scan_report_url or f"https://www.virustotal.com/gui/file/{scan.checksum}",
        "engines": engines,
    }
    return render(request, 'scan_reports.html', context)


@login_required
def dashboard(request):
    reports = UploadedFile.objects.filter(
        user=request.user).order_by('-uploaded_at')
    return render(request, 'dashboard.html', {'reports': reports})


def file_integrity_status(request):
    files = UploadedFile.objects.filter(
        user=request.user).order_by('-uploaded_at')
    return render(request, 'file_integrity_status.html', {'files': files})


def scan_reports_list(request):
    reports = UploadedFile.objects.all().order_by('-uploaded_at')
    return render(request, 'scan_reports_list.html', {'reports': reports})


@login_required
@require_POST
def delete_scanned_url(request, url_id):
    # Check for AJAX request in a modern way
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        try:
            scanned_url = ScannedURL.objects.get(id=url_id, user=request.user)
            scanned_url.delete()
            return JsonResponse({"success": True})
        except ScannedURL.DoesNotExist:
            return JsonResponse({"success": False, "error": "Not found"}, status=404)
    return JsonResponse({"success": False, "error": "Invalid request"}, status=400)


@login_required
def delete_report(request, report_id):
    report = get_object_or_404(UploadedFile, id=report_id, user=request.user)
    if request.method == "POST":
        report.delete()
        messages.success(request, "Report deleted successfully.")
        return redirect('scan_reports_list')
    return redirect('scan_reports_list')


# Add this helper for checksum
def calculate_file_checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# --- Replace the old scan_file_for_malware function with the new v3 API version ---

def scan_file_for_malware(file_path):
    """
    Scan a file using VirusTotal v3 API.
    """
    VIRUSTOTAL_API_KEY = '5f754625f022fb45c2bc52b7e958284b9d53cfa12456ca73ad21ab5d6d2463ef'
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        data = response.json()
        analysis_id = data['data']['id']
        # Poll for analysis results
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data['data']['attributes']['status']
                if status == 'completed':
                    stats = analysis_data['data']['attributes']['stats']
                    positives = stats.get('malicious', 0) + \
                        stats.get('suspicious', 0)
                    total = sum(stats.values())
                    return {
                        'result': json.dumps(analysis_data),
                        'date': timezone.now(),
                        'positives': positives,
                        'total': total,
                        'status': 'INFECTED' if positives > 0 else 'CLEAN'
                    }
            time.sleep(2)
    return {
        'result': 'Scan failed',
        'date': timezone.now(),
        'positives': None,
        'total': None,
        'status': 'UNKNOWN'
    }


@csrf_exempt
def ajax_file_upload(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']

        # Ensure the tmp directory exists inside your project
        project_tmp_dir = os.path.join(settings.MEDIA_ROOT, '..', 'tmp')
        project_tmp_dir = os.path.abspath(project_tmp_dir)
        os.makedirs(project_tmp_dir, exist_ok=True)

        temp_file = tempfile.NamedTemporaryFile(
            delete=False, dir=project_tmp_dir)
        try:
            for chunk in uploaded_file.chunks():
                temp_file.write(chunk)
            temp_file.close()  # Ensure file is closed before reading

            checksum = calculate_file_checksum(temp_file.name)
            scan_result = scan_file_for_malware(temp_file.name)
        finally:
            try:
                os.unlink(temp_file.name)
            except Exception as e:
                print("Temp file delete failed:", e)

        UploadedFile.objects.create(
            user=request.user if request.user.is_authenticated else User.objects.first(),
            file_name=uploaded_file.name,
            uploaded_at=timezone.now(),
            checksum=checksum,
            scan_result=scan_result['result'],
            scan_date=scan_result['date'],
            scan_positives=scan_result['positives'],
            scan_total=scan_result['total'],
            status=scan_result['status'],
        )
        return JsonResponse({'status': 'ok'})
    return JsonResponse({'status': 'fail'}, status=400)


@login_required
def rescan_file(request, scan_id):
    uploaded_file = get_object_or_404(
        UploadedFile, id=scan_id, user=request.user)
    file_path = uploaded_file.file.path  # <-- THIS IS THE FIX
    scan_result = scan_file_for_malware(file_path)
    try:
        result_json = json.loads(scan_result['result'].replace("'", '"'))
    except Exception:
        result_json = {}
    uploaded_file.scan_result = scan_result['result']
    uploaded_file.scan_date = scan_result['date']
    uploaded_file.scan_positives = scan_result['positives']
    uploaded_file.scan_total = scan_result['total']
    uploaded_file.status = scan_result['status']
    uploaded_file.scan_report_url = result_json.get('permalink')
    uploaded_file.save()
    messages.success(request, "File re-scanned successfully.")
    return redirect('scan_reports', scan_id=scan_id)


@login_required
def delete_file(request, file_id):
    file = get_object_or_404(UploadedFile, id=file_id)
    if request.method == "POST":
        file.delete()
        return redirect('file_integrity_status')
    return redirect('file_integrity_status')
