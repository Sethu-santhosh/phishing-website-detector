from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from .forms import URLCheckForm, RegisterForm
from .models import URLCheck
from .detector import detect_phishing


def home(request):
    result = None

    form = URLCheckForm(request.POST or None)

    if request.method == "POST" and form.is_valid():

        url = form.cleaned_data["url"]

        # Detect phishing and get website age information
        score, label, reasons, age_text, registration_date = detect_phishing(url)

        result = {
            "url": url,
            "score": score,
            "label": label,
            "reasons": reasons,
            "age": age_text,
            "registration_date": registration_date,
        }

        # Save the result in database
        URLCheck.objects.create(
            user=request.user if request.user.is_authenticated else None,
            url=url,
            score=score,
            result=label,
            reasons="\n".join(reasons),
        )

    return render(
        request,
        "home.html",
        {
            "form": form,
            "result": result,
        },
    )


def register(request):

    if request.user.is_authenticated:
        return redirect("home")

    form = RegisterForm(request.POST or None)

    if request.method == "POST" and form.is_valid():

        user = form.save()

        login(request, user)

        return redirect("home")

    return render(
        request,
        "register.html",
        {
            "form": form,
        },
    )


def user_login(request):

    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(
            request,
            username=username,
            password=password,
        )

        if user is not None:

            login(request, user)

            return redirect("home")

        messages.error(
            request,
            "Invalid username or password."
        )

    return render(request, "login.html")


def user_logout(request):

    logout(request)

    return redirect("home")


@login_required
def history(request):

    checks = URLCheck.objects.filter(
        user=request.user
    ).order_by("-checked_at")

    return render(
        request,
        "history.html",
        {
            "checks": checks,
        },
    )
