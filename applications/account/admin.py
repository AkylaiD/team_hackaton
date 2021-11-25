from django.contrib import admin
from django.contrib.auth.models import Group

from applications.account.models import User

admin.site.register(User)
admin.site.unregister(Group)
