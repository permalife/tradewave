from django.db import models

# Create your models here.

class Credit(models.Model):
    producer = models.CharField(max_length=100)
    create_date = models.DateTimeField('date created')

