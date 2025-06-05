# urls.py
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),

    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.profile, name='profile'),

    path('upload/', views.upload_file, name='upload_file'),
    path('ajax-upload/', views.ajax_file_upload, name='ajax_file_upload'),

    path('check_integrity/<int:file_id>/',
         views.check_integrity, name='check_integrity'),
    path('check_malware/<int:file_id>/',
         views.check_malware, name='check_malware'),
    path('success/', views.success, name='success'),

    path('check-url-reputation/', views.check_url_reputation,
         name='url_reputation_checker'),

    path('execute-scan-for-malware/', views.execute_scan_for_malware,
         name='execute_scan_for_malware'),
    path('scan-reports/', views.scan_reports_list, name='scan_reports_list'),
    path('scan-reports/<int:scan_id>/', views.scan_reports, name='scan_reports'),
    path('scan-reports/<int:scan_id>/rescan/',
         views.rescan_file, name='rescan_file'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('file-integrity-status/', views.file_integrity_status,
         name='file_integrity_status'),

    path('delete-scanned-url/<int:url_id>/',
         views.delete_scanned_url, name='delete_scanned_url'),

    path('scan-reports/delete/<int:report_id>/',
         views.delete_report, name='delete_report'),

    path('delete-file/<int:file_id>/', views.delete_file, name='delete_file'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
