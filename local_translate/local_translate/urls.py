from django.urls import path
from . import trans, spider, middleware

urlpatterns = [
    path('trans', trans.trans),
    path('spider', spider.spider),
    path('', middleware.index),
    path('get_token', middleware.token),
]
