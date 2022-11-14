
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
    path('getzohocredential',views.GetZohoCredential_cls.as_view()),
    path('sendredirecturiemail',views.SendRedirectUriEmail.as_view()),
    path('vehicleregistration',views.VehicleRegistration.as_view()),
    path('editvehicleregistration',views.EditVehicleRegistration.as_view()),
    path('vehiclelogin',views.VehicleLogin.as_view()),
    path('getvehicledetail',views.GetVehicleDetail.as_view()),
    path('deletevehicle',views.DeleteVehicle.as_view()),
    path('vehiclelist',views.VehicleList_fun.as_view()),
    path('addslotinfo',views.AddSlotInfo.as_view()),
    path('editslotinfo',views.EditSlotInfo.as_view()),
    path('slotlist',views.SlotList_fun.as_view()),
    path('getslotdetail',views.GetSlotDetail.as_view()),
    path('deleteslot',views.DeleteSlot.as_view()),
    path('addwarehousecoordinates',views.AddCoordinatesUser.as_view()),
    path('fetchinvoicedata',views.FetchInvoiceData.as_view()),
    path('additemapi',views.AddItemAPI.as_view()),
    path('itemlist',views.ItemList_fun.as_view()),
    path('getitemdetail',views.GetItemDetail.as_view()),
    path('edititemInfo',views.EditItemInfo.as_view()),
    path('getorderbyslotdetail',views.GetOrderbySlotDetail.as_view()),
    path('rootoptimazation',views.RootOptimazationAPI.as_view()),
    path('getorderwithcoordinateslist',views.GetOrderwithCoordinatesList.as_view()),
]