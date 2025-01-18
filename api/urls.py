from django.urls import path, include


urlpatterns = [
    # =================================================================
    # *** User auths API Endpoints ***
    path("auth/", include("accounts.urls")),
    # =================================================================
]
