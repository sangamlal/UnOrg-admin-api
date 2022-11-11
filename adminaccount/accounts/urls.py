
from django.urls import path
from accounts import views

urlpatterns = [
   
    path('createuser',views.SignupUser.as_view()),
    path('loginapi',views.UserLoginView.as_view()),
    path('sendzohoregistrationlink',views.SendZohoRegistrationLink_fun.as_view()),
    path('userlist',views.UserList_fun.as_view()),
    path('getuserdetail',views.GetUserDetail_fun.as_view()),
    path('addzohoaccount',views.AddZohoCredential.as_view()),
    path('velidateaccesstoken',views.VelidateAccessToken.as_view()),
]