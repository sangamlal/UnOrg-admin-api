
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
    path('fetchinvoicedata',views.NewFetchInvoiceData.as_view()),
    path('additemapi',views.AddItemAPI.as_view()),
    path('itemlist',views.ItemList_fun.as_view()),
    path('getitemdetail',views.GetItemDetail.as_view()),
    path('edititemInfo',views.EditItemInfo.as_view()),
    path('getorderbyslotdetail',views.GetOrderbySlotDetail.as_view()),
    path('rootoptimazation',views.RootOptimazationAPI.as_view()),
    path('getorderwithcoordinateslist',views.GetOrderwithCoordinatesList.as_view()),
    path('getorderwithoutcoordinateslist',views.GetOrderwithoutCoordinatesList.as_view()),
    path('orders_delivery',views.orders_delivery.as_view()),
    path('getapporderdetail',views.GetAppOrderDetail.as_view()),
    path('getapporderlist',views.GetAppOrderList_f.as_view()),
    path('getlastinvoiceupdateddate',views.GetLastInvoiceUpdatedDate_fun.as_view()),
    path('assignordertovehicle',views.AssignOrdertoVehicle_fun.as_view()),
    path('allocatedtovehicledeliveryorderlist',views.AllocatedToVehicleDeliveryOrderList_f.as_view()),
    path('publishorderdeliverylist',views.PublishOrderDeliveryList_fun.as_view()),
    path('GetZohoCredentialbyuserid',views.GetZohoCredentialByUserID_fun.as_view()),
    path('testcasecheckapi',views.TestCaseCheckAPI_fun.as_view()),
    path('assignserialnumbertoorders',views.AssignSerialNumberToOrders_fun.as_view()),
    path('historydeliveryorderlist',views.HistoryAllocatedToVehicleDeliveryOrderList_f.as_view()),
    path('rootoptimizeorderdeliverylist',views.RootOptimizeOrderDeliveryList_f.as_view()),
    path('manally_assign_list',views.manally_assign_list.as_view()),
    path('allvehiclelist',views.AllVehicleList_fun.as_view()),
    path('is_vehicle_free',views.is_vehicle_free.as_view()),
    path('clear_data',views.clear_data.as_view()),
    path('addbranchesapi',views.AddBranchesAPI.as_view()),
    path('warehouse_branches_list',views.warehouse_branches_list_fun.as_view()),
    path('check_is_vehicle_free',views.Check_Is_vehicle_Free_fun.as_view()),
]