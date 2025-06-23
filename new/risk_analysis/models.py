from django.db import models

# Create your models here.

# 23/04/25



# class PacketAnalysis(models.Model):
#     timestamp = models.DateTimeField(auto_now_add=True)
#     source_ip = models.CharField(max_length=45)
#     destination_ip = models.CharField(max_length=45)
#     source_port = models.IntegerField(null=True, blank=True)
#     destination_port = models.IntegerField(null=True, blank=True)
#     protocol = models.CharField(max_length=50)
#     ndpi_protocol = models.CharField(max_length=50, blank=True)
#     severity = models.CharField(max_length=10, choices=[('HIGH', 'High'), ('MEDIUM', 'Medium'), ('LOW', 'Low')])
#     risk_score = models.IntegerField(default=0)
#     risks = models.JSONField(blank=True, null=True)
#     details = models.JSONField()
#     description = models.TextField(blank=True)

#     def __str__(self):
#         return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.severity})"

#     class Meta:
#         ordering = ['-timestamp']



#24/04/25


# from django.db import models

# class PacketAnalysis(models.Model):
#     first_seen = models.DateTimeField(null=True, blank=True)
#     last_seen = models.DateTimeField(null=True, blank=True)
#     source_ip = models.CharField(max_length=45)
#     destination_ip = models.CharField(max_length=45)
#     source_port = models.IntegerField(null=True, blank=True)
#     destination_port = models.IntegerField(null=True, blank=True)
#     protocol = models.CharField(max_length=50)
#     ndpi_protocol = models.CharField(max_length=50, blank=True)
#     risks = models.JSONField(blank=True, null=True)
#     details = models.JSONField()
#     description = models.TextField(blank=True)

#     def __str__(self):
#         return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

#     class Meta:
#         ordering = ['-first_seen']












#24/04/25



# from django.db import models

# class Settings(models.Model):
#     log_retention_minutes = models.PositiveIntegerField(default=60, help_text="Retention period for general logs in minutes")

#     def __str__(self):
#         return f"Log Retention: {self.log_retention_minutes} minutes"

# class PacketAnalysis(models.Model):
#     first_seen = models.DateTimeField(null=True, blank=True)
#     last_seen = models.DateTimeField(null=True, blank=True)
#     source_ip = models.CharField(max_length=45)
#     destination_ip = models.CharField(max_length=45)
#     source_port = models.IntegerField(null=True, blank=True)
#     destination_port = models.IntegerField(null=True, blank=True)
#     protocol = models.CharField(max_length=50)
#     ndpi_protocol = models.CharField(max_length=50, blank=True)
#     risks = models.JSONField(blank=True, null=True)
#     details = models.JSONField()
#     description = models.TextField(blank=True)

#     def __str__(self):
#         return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

#     class Meta:
#         ordering = ['-first_seen']

# class AnalysisLog(models.Model):
#     created_at = models.DateTimeField(auto_now_add=True)
#     message = models.TextField()
#     details = models.JSONField(blank=True, null=True)

#     def __str__(self):
#         return f"{self.created_at}: {self.message}"

# class SevereFlowLog(models.Model):
#     created_at = models.DateTimeField(auto_now_add=True)
#     first_seen = models.DateTimeField()
#     source_ip = models.CharField(max_length=45)
#     destination_ip = models.CharField(max_length=45)
#     source_port = models.IntegerField(null=True, blank=True)
#     destination_port = models.IntegerField(null=True, blank=True)
#     protocol = models.CharField(max_length=50)
#     ndpi_protocol = models.CharField(max_length=50, blank=True)
#     risks = models.JSONField()
#     details = models.JSONField()

#     def __str__(self):
#         return f"SEVERE: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"








# 25/04/25


from django.db import models

class Settings(models.Model):
    log_retention_minutes = models.PositiveIntegerField(default=60, help_text="Retention period for general logs in minutes")

    def __str__(self):
        return f"Log Retention: {self.log_retention_minutes} minutes"

class PacketAnalysis(models.Model):
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    source_ip = models.CharField(max_length=45)
    destination_ip = models.CharField(max_length=45)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=50)
    ndpi_protocol = models.CharField(max_length=50, blank=True)
    risks = models.JSONField(blank=True, null=True)
    details = models.JSONField()
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

    class Meta:
        ordering = ['first_seen']

class SevereFlowLog(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    first_seen = models.DateTimeField()
    source_ip = models.CharField(max_length=45)
    destination_ip = models.CharField(max_length=45)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=50)
    ndpi_protocol = models.CharField(max_length=50, blank=True)
    risks = models.JSONField()
    details = models.JSONField()

    def __str__(self):
        return f"SEVERE: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"



