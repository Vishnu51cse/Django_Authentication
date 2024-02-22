
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True)
    dob = models.DateField()
    password = models.CharField(max_length=100)

    def __str__(self):
        return self.name