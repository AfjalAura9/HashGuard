from .forms import DirectoryScanForm
from .forms import URLReputationForm
import hashlib
import os
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
from django.core.management import call_command
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

VIRUSTOTAL_API_KEY = '5f754625f022fb45c2bc52b7e958284b9d53cfa12456ca73ad21ab5d6d2463ef'


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
    uploaded_files = UploadedFile.objects.filter(user=request.user)
    integrity_status = {}
    for file in uploaded_files:
        if file.status == 'INTEGRITY_CHECK_PASSED':
            integrity_status[file.id] = 'Integrity check passed. The file is intact.'
        elif file.status == 'MODIFIED':
            integrity_status[file.id] = 'File integrity check failed. The file has been modified.'
    return render(request, 'profile.html', {'uploaded_files': uploaded_files, 'integrity_status': integrity_status})


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
        uploaded_file.scan_result = str(json_response)
        uploaded_file.scan_date = timezone.now()
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
            messages.error(request, "Malware detected in the file.")
        else:
            uploaded_file.status = 'CLEAN'
            messages.success(request, "File is clean and safe.")
    else:
        messages.error(
            request, "Failed to check for malware. Please try again later.")
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
    uploaded_file = get_object_or_404(
        UploadedFile, id=scan_id, user=request.user)
    return render(request, 'scan_reports.html', {'file': uploaded_file})


@login_required
def dashboard(request):
    reports = UploadedFile.objects.filter(
        user=request.user).order_by('-uploaded_at')
    return render(request, 'dashboard.html', {'reports': reports})


def file_integrity_status(request):
    # Your logic here
    return render(request, 'file_integrity_status.html')


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
def delete_scan_report(request, report_id):
    if request.method == "POST":
        report = get_object_or_404(UploadedFile, id=report_id)
        report.delete()
    return redirect('scan_reports_list')
