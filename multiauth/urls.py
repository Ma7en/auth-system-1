"""
URL configuration for multiauth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include

#
from django.conf import settings
from django.conf.urls.static import static

#
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

#
swagger_view = get_schema_view(
    openapi.Info(
        title="Authentication API Documentation",
        default_version="v1",
        description="API for Authentication",
        contact=openapi.Contact(email="mazen7saad@gmail.com"),
        license=openapi.License(name="Mazen Saad"),
    ),
    public=True,
    # permission_classes=(AllowAny,),
)

urlpatterns = [
    # =================================================================
    path(
        "",
        swagger_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    # =================================================================
    path("admin/", admin.site.urls),
    # =================================================================
    path("api/v1/", include("api.urls")),
    # =================================================================
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
