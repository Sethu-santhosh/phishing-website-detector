from django.contrib import admin
from django.urls import path

from checker.views import (
    home,
    register,
    user_login,
    user_logout,
    history,
    dashboard,
)


urlpatterns = [
    path("admin/", admin.site.urls),

    path("", home, name="home"),

    path("register/", register, name="register"),

    path("login/", user_login, name="login"),

    path("logout/", user_logout, name="logout"),

    path("history/", history, name="history"),

    path("dashboard/", dashboard, name="dashboard"),
]
