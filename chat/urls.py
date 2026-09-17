# chat/urls.py
from django.contrib.auth import views as auth_views
from django.urls import path
from . import views

app_name = "chat"

urlpatterns = [
    path("", views.inbox_view, name="inbox"),

    path("signup/", views.signup_view, name="signup"),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="chat/login.html"),
        name="login",
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page="chat:login"),
        name="logout",
    ),

    # These two MUST come last -- <str:username> would otherwise
    # swallow "signup/", "login/", etc.
    path("account/rotate-keys/", views.rotate_keys_view, name="rotate_keys"),
    path("<str:username>/", views.room_chat_view, name="room"),
    path("<str:username>/send/", views.send_to_room, name="send"),
]