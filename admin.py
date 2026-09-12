from django.contrib import admin
from .models import URLCheck
@admin.register(URLCheck)
class URLCheckAdmin(admin.ModelAdmin):
    list_display=("url","result","score","user","checked_at")
    list_filter=("result","checked_at")
    search_fields=("url","reasons")
