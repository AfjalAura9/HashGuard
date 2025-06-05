# models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver


class UploadedFile(models.Model):
    STATUS_CHOICES = (
        ('CLEAN', 'Clean'),
        ('INFECTED', 'Infected'),
        ('MODIFIED', 'Modified'),
        ('INTEGRITY_CHECK_PASSED', 'Integrity Check Passed'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/',
                            null=True, blank=True)  # Make optional
    file_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    checksum = models.CharField(max_length=64, blank=True, null=True)
    scan_result = models.TextField(blank=True, null=True)
    scan_date = models.DateTimeField(blank=True, null=True)
    scan_positives = models.IntegerField(blank=True, null=True)
    scan_total = models.IntegerField(blank=True, null=True)
    status = models.CharField(max_length=32, default='PENDING')
    scan_report_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.file_name


class SuspiciousActivity(models.Model):
    EVENT_CHOICES = [
        ('FILE_UPLOAD', 'File Upload'),
        ('INTEGRITY_CHECK_FAILURE', 'Integrity Check Failure'),
        ('MALWARE_DETECTION', 'Malware Detection'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES)
    details = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def get_event_type_display(self):
        return dict(self.EVENT_CHOICES).get(self.event_type, self.event_type)


class ScannedURL(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    status = models.CharField(max_length=16)  # e.g. 'active', 'inactive'
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} ({self.status})"


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', blank=True, null=True)

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
