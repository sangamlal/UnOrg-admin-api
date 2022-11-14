from django.shortcuts import render
from ast import Try
import imp
from .distance_matrix import  coordinates_preprocesing
import json
from operator import truediv
from select import select
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
# Create your views here.
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.exceptions import APIException
from datetime import datetime
from django.core.mail import EmailMultiAlternatives
from .serializers import *
import re
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, zohoaccount,vehicleinfo,slotinfo
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.core import serializers
import requests
import hashlib
# Create your views here.

def checkcoordinate(s):    
    try:
        # print(s," ", s.split(' '))
        if len(s.split(' ')) == 2:
            if [float(s.split(' ')[0]), float(s.split(' ')[1])]:
                return True
            return False
        deg0, dec0 = s.split(' ')[1].split('°')
        deg1, dec1 = s.split(' ')[-1].split('°')

        deg0 = float(deg0)
        deg1 = float(deg1)
        minu0, seco0 = dec0.split("'")
        minu1, seco1 = dec1.split("'")
        seco0 = float(re.findall("\d+\.\d+", seco0)[0])
        seco1 = float(re.findall("\d+\.\d+", seco1)[0])
        n1 = float(deg0) + float(minu0) / 60 + float(seco0) / (60 * 60)
        n2 = float(deg1) + float(minu1) / 60 + float(seco1) / (60 * 60)
        return True
    except Exception as e:
        print(e)
        return False
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# Define Create User (Register User) API with only post request


class SignupUser(APIView):
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = SignupUserSerializer(data=request.data)
            if serializer.is_valid():
                user = User.objects.create(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    first_name=serializer.validated_data.get('first_name', ''),
                    last_name=serializer.validated_data.get('last_name', ''),
                    mobile=serializer.validated_data.get('mobile', ''),
                    is_zoho_active=0
                )
                user.set_password(serializer.validated_data['password'])
                user.save()
                refresh = RefreshToken.for_user(user)
                if user:
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'username': str(user),
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'message': 'User created'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'User not created',
                        'message': 'data not created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request):
        try:
            # print("iiiiiiiii ",request.id)
            serializer = EditUserProfileSerializer(data=request.data)
            if serializer.is_valid():
                userinfo = User.objects.filter(id=serializer.data.get('id'))
                if userinfo:

                    # print("--------------",userinfo.get("username"))
                    userinfo.update(
                        username=serializer.validated_data.get('username'),
                        email=serializer.validated_data.get('email'),
                        first_name=serializer.validated_data.get(
                            'first_name', ''),
                        last_name=serializer.validated_data.get(
                            'last_name', ''),
                        mobile=serializer.validated_data.get('mobile', '')
                    )
                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'message': 'User updated successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    print("================")
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:

                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request):
        try:
            # print("iiiiiiiii ",request.id)
            deletestatus, userinfo = User.objects.filter(
                id=request.data.get('id')).delete()
            # print(deletestatus,"--------------",userinfo)
            if deletestatus:
                json_data = {
                    'status_code': 205,
                    'status': 'Success',
                    'message': 'User deleted successfully'
                }
                return Response(json_data, status.HTTP_205_RESET_CONTENT)
            else:
                # print("================")
                json_data = {
                    'status_code': 204,
                    'status': 'Success',
                    'message': 'User not found'
                }
                return Response(json_data, status.HTTP_204_NO_CONTENT)

        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(APIView):

    def post(self, request, format=None):
        try:
            serializer = UserLoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                username = serializer.data.get('username')
                password = serializer.data.get('password')
                user = authenticate(username=username, password=password)
                if user is not None:
                    data = User.objects.get(username=user)
                    newdata = {
                        "id": data.id,
                        "username": data.username,
                        "email": data.email,
                        "first_name": data.first_name,
                        "last_name": data.last_name,
                        "mobile": data.mobile,
                        "is_active": data.is_active,
                        "is_superuser": data.is_superuser,
                        "is_zoho_active": data.is_zoho_active,
                    }
                    print("-----------------", newdata)
                    print("-----------------", type(data))
                    token = get_tokens_for_user(user)
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'data': newdata,
                        'refresh': str(token.get("refresh")),
                        'access': str(token.get("access")),
                        'message': 'User login success'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)

                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Failed',
                        'error': "User name or Password is incorrect",
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class VelidateAccessToken(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        try:
            
            datacheck=User.objects.filter(email=request.user.email)
            #Check Data 
            if datacheck:
                #Getting data of user
                data = User.objects.get(email=request.user.email)
                newdata = {
                    "id": data.id,
                    "username": data.username,
                    "email": data.email,
                    "first_name": data.first_name,
                    "last_name": data.last_name,
                    "mobile": data.mobile,
                    "is_active": data.is_active,
                    "is_superuser": data.is_superuser,
                    "is_zoho_active": data.is_zoho_active,
                }
                
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'data': newdata,
                    'message': 'User token validated'
                }
                return Response(json_data, status.HTTP_200_OK)

            else:
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'data': '',
                    'error': "User not found",
                }
                return Response(json_data, status.HTTP_200_OK)
        
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class SendZohoRegistrationLink_fun(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            serializer = SendZohoRegistrationLinkSerializer(data=request.data)
            if serializer.is_valid():
                checckuserid=User.objects.filter(id=serializer.data.get('userid'))
                if not checckuserid:
                    json_data = {
                        'status_code': 200,
                        'status': 'Failed',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                userid=User.objects.get(id=serializer.data.get('userid'))
                userid=userid
                print("---llll ",userid)
                zohodata = zohoaccount.objects.create(
                    userid=userid,
                    clientid='',
                    clientsecret='',
                    accesstoken='',
                    refreshtoken='',
                    redirecturi='',
                    is_deleted=0,
                    created_at=datetime.now(),
                )
                zohodata.save()
                print("-----------",zohodata.id)
                # html_message="https://api-console.zoho.in"
                emailBody = """ 
                    <body style="background-color:grey">
                        <table align="center" border="0" cellpadding="0" cellspacing="0"
                            width="550" bgcolor="white" style="border:2px solid black">
                            <tbody>
                                <tr>
                                    <td align="center">
                                        <table align="center" border="0" cellpadding="0"
                                            cellspacing="0" class="col-550" width="550">
                                            <tbody>
                                                <tr>
                                                    <td align="center"
                                                        style="background-color: #4cb96b;
                                                            height: 50px;">
                                                        
                                                        <p style="color:white;font-weight:bold;">
                                                            Zoho Registration URL
                                                            
                                                        </p>
                                                        <a href="https://api-console.zoho.in" style="text-decoration: none;">
                                                        https://api-console.zoho.in
                                                        </a>
                                                        <br>
                                                        <strong>Open This URL To Enter Credentials</strong>
                                                        http://localhost:5173/add-credential?id="""+str(zohodata.id)+""""
                                                        <strong>Redirect URL</strong>
                                                        http://localhost:5173/add-access
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </body> """
                emailSubject = """ Zoho User Registration """
                # nirmam.sanghvi@timesgroup.com
                # subject, from_email, to, bcc = emailSubject, 'ascent@timesgroup.com', ['nirmam.sanghvi@timesgroup.com'], ['swapnil@rozgaarindia.com','accounts@rozgaarindia.com']
                subject, from_email, to = emailSubject, 'UnOrg <shwetanshumishra1999@gmail.com>', [
                    serializer.data.get('email')]
                html_content = emailBody
                msg = EmailMultiAlternatives(
                    subject, html_content, from_email, to)
                msg.attach_alternative(html_content, "text/html")
                print("Client Mail sent successfullly")
                msg.send()
                if msg:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'zohoaccountid': zohodata.id,
                        'message': 'Email Send Successfully'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Failed',
                        'message': 'Email not send'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserList_fun(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            print("--------------")

            activeuserinfo = User.objects.filter(
                is_zoho_active=1, is_superuser=0)
            inactiveuserinfo = User.objects.filter(
                is_zoho_active=0, is_superuser=0)
            activeuserlist = [{"id": data.id, "username": data.username, "first_name": data.first_name, "mobile": data.mobile, "email": data.email,
                               "first_name": data.first_name, "last_name": data.last_name, 'is_zoho_active': data.is_zoho_active} for data in activeuserinfo]
            inactiveuserlist = [{"id": data.id, "username": data.username, "first_name": data.first_name, "mobile": data.mobile, "email": data.email,
                                 "first_name": data.first_name, "last_name": data.last_name, 'is_zoho_active': data.is_zoho_active} for data in inactiveuserinfo]
            # print(list(activeuserinfo),"============",activeuserlist)
            if activeuserinfo or inactiveuserinfo:
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'activeuser': activeuserlist,
                    'inactiveuser': inactiveuserlist,
                    'message': 'User found'
                }
                return Response(json_data, status.HTTP_200_OK)
            else:
                print("================")
                json_data = {
                    'status_code': 204,
                    'status': 'Success',
                    'message': 'User not found'
                }
                return Response(json_data, status.HTTP_204_NO_CONTENT)

        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserDetail_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            print("--------------")

            # userdata = User.objects.filter(id=request.data.get("id") if request.data.get("id") else 0)
            # userdetail = [{"id": data.id, "username": data.username, "first_name": data.first_name, "mobile": data.mobile,
            #                "email": data.email, "first_name": data.first_name, "last_name": data.last_name} for data in userdata]
            datacheck=User.objects.filter(id=request.data.get("id") if request.data.get("id") else 0)
            print("------",datacheck)
            #Check Data 
            if datacheck:
                #Getting data of user
                data = User.objects.get(id=request.data.get("id") if request.data.get("id") else 0)
                print("==========",data)
                newdata = {
                        "id": data.id,
                        "username": data.username,
                        "email": data.email,
                        "first_name": data.first_name,
                        "last_name": data.last_name,
                        "mobile": data.mobile,
                        "is_active": data.is_active,
                        "is_superuser": data.is_superuser,
                        "is_zoho_active": data.is_zoho_active,
                        "longitude": data.longitude,
                        "latitude": data.latitude,
                    }
            
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'data': newdata,
                    'message': 'User found'
                }
                return Response(json_data, status.HTTP_200_OK)
            else:
                print("================")
                json_data = {
                    'status_code': 204,
                    'status': 'Success',
                    'data': '',
                    'message': 'User not found'
                }
                return Response(json_data, status.HTTP_204_NO_CONTENT)

        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class AddZohoCredential(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = ZohoAccountSerializer(data=request.data)
            if serializer.is_valid():
               
                datauser = zohoaccount.objects.filter(id=serializer.data.get(
                        'zohoaccountid', ''))
                if datauser:
                    getdatauser = zohoaccount.objects.get(id=serializer.data.get(
                        'zohoaccountid', ''))
                    print("===========")
                    datauser.update( clientid=serializer.validated_data['clientid'],
                        clientsecret=serializer.validated_data.get(
                            'clientsecret', ''),
                        accesstoken=serializer.validated_data.get(
                            'accesstoken', ''),
                        refreshtoken=serializer.validated_data.get(
                            'refreshtoken', ''),
                        redirecturi=serializer.validated_data.get(
                            'redirecturi', ''),)
                    print("=========get data==", datauser)
                    # Email Send Process Start
                
                    # clientid = serializer.validated_data.get('clientid', '')
                    # redirecturi = serializer.validated_data.get('redirecturi', '')
                    # # print(redirecturi, "-------------", clientid)
                    # emailBody = "UnOrg code : "+str(getdatauser.id)+"<br>https://accounts.zoho.com/oauth/v2/auth?scope=ZohoBooks.invoices.CREATE,ZohoBooks.invoices.READ,ZohoBooks.invoices.UPDATE,ZohoBooks.invoices.DELETE&client_id=" + \
                    #     clientid+"&state="+str(getdatauser.id)+"&response_type=code&redirect_uri=" + \
                    #     redirecturi+"&access_type=offline"
                    # emailSubject = "Get Zoho Code "
                    # subject, from_email, to = emailSubject, 'UnOrg <shwetanshumishra1999@gmail.com>', [
                    #     getdatauser.userid.email]
                    # html_content = emailBody
                    # msg = EmailMultiAlternatives(
                    #     subject, html_content, from_email, to)
                    # msg.attach_alternative(html_content, "text/html")
                    # print("Client Mail sent successfullly")
                    # msg.send()
                    # Email Send Process Start
                
                
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'zohoaccountid': getdatauser.id,
                        'message': 'Data saved'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Data not saved'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request):
        try:
            serializer = EditZohoAccountSerializer(data=request.data)
            if serializer.is_valid():
                userinfo = zohoaccount.objects.get(
                    id=serializer.validated_data.get('id'))
                code = serializer.validated_data.get('code', '')
                client_id = userinfo.clientid
                client_secret = userinfo.clientsecret
                redirect_uri = userinfo.redirecturi

                url = "https://accounts.zoho.in/oauth/v2/token?code="+code+"&client_id="+client_id + \
                    "&client_secret="+client_secret+"&redirect_uri=" + \
                    redirect_uri+"&grant_type=authorization_code"

                payload = "\r\n  \r\n"
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': '6e73717622=3bcf233c3836eb7934b6f3edc257f951; _zcsr_tmp=578d48be-da9a-4183-bfc8-d98f34d13b27; iamcsr=578d48be-da9a-4183-bfc8-d98f34d13b27'
                }

                response = requests.request(
                    "POST", url, headers=headers, data=payload).json()

                print("--------------", response.get('access_token', ''))

                if response.get('access_token'):

                    userinfo.accesstoken = response.get('access_token', '')
                    userinfo.refreshtoken = response.get('refresh_token', '')
                    userinfo.save()
                    datauser = User.objects.filter(id=userinfo.userid.id)
                    datauser.update(is_zoho_active=1)

                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Token updated successfully'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    print("================")
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': response.get("error")
                    }
                    return Response(json_data, status.HTTP_200_OK)

            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class GetZohoCredential_cls(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        try:
            serializer = GetZohoCredentialSerializer(data=request.data)
            if serializer.is_valid(raise_exception=False):

                zohoid = serializer.data.get('zohoaccountid')
                datacheck=zohoaccount.objects.filter(id=zohoid)
                print("------",datacheck)
                #Check Data 
                if datacheck:
                    #Getting data of user
                    data = zohoaccount.objects.get(id=zohoid)
                    print("==========",data)
                    newdata = {
                        "id": data.id,
                        "clientid": data.clientid,
                        "clientsecret": data.clientsecret,
                        "accesstoken": data.accesstoken,
                        "refreshtoken": data.refreshtoken,
                        "created_at": data.created_at,
                        "is_deleted": data.is_deleted,
                        "redirecturi": data.redirecturi,
                        "userid": data.userid.id
                    }
                    print("----------",newdata)
                   
                    json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'data': newdata,
                    'message': 'Data found'
                    }
                    return Response(json_data, status.HTTP_200_OK)

                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Failed',
                        'data': '',
                        'error': "Data not found",
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)




class SendRedirectUriEmail(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = SendRedirectUriEmailSerializer(data=request.data)
            if serializer.is_valid():
               
                datauser = zohoaccount.objects.filter(id=serializer.data.get(
                        'zohoaccountid', ''))
                if datauser:
                    getdatauser = zohoaccount.objects.get(id=serializer.data.get(
                        'zohoaccountid', ''))
                    print("===========")
                    
                    print("=========get data==", datauser)
                    print("=========get data==", getdatauser.userid.email)
                    # Email Send Process Start
                
                    clientid = getdatauser.clientid
                    redirecturi = getdatauser.redirecturi
                    # print(redirecturi, "-------------", clientid)
                    emailBody = "UnOrg code : "+str(getdatauser.id)+"<br>https://accounts.zoho.com/oauth/v2/auth?scope=ZohoBooks.invoices.CREATE,ZohoBooks.invoices.READ,ZohoBooks.invoices.UPDATE,ZohoBooks.invoices.DELETE&client_id=" + \
                        clientid+"&state="+str(getdatauser.id)+"&response_type=code&redirect_uri=" + \
                        redirecturi+"&access_type=offline"
                    emailSubject = "Get Zoho Code "
                    subject, from_email, to = emailSubject, 'UnOrg <shwetanshumishra1999@gmail.com>', [
                        getdatauser.userid.email]
                    html_content = emailBody
                    msg = EmailMultiAlternatives(
                        subject, html_content, from_email, to)
                    msg.attach_alternative(html_content, "text/html")
                    print("Client Mail sent successfullly")
                    msg.send()
                    # Email Send Process Start
                
                
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'zohoaccountid': getdatauser.id,
                        'message': 'Email send successfully'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)





class VehicleRegistration(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = VehicleRegistrationSerializer(data=request.data)
            if serializer.is_valid():
                vechicleinfo = vehicleinfo.objects.create(
                    userid=serializer.validated_data['userid'],
                    password=serializer.validated_data.get('password') if serializer.validated_data.get('password') else '',
                    vehiclename=serializer.validated_data.get('vehiclename'),
                    maxorders=serializer.validated_data.get('maxorders'),
                    weightcapacity=serializer.validated_data.get('weightcapacity'),
                    phone=serializer.validated_data.get('phone', ''),
                    is_deleted=0,
                    created_at=datetime.now()
                )
                vechicleinfo.save()
                if vechicleinfo:
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'vechicleinfoid': vechicleinfo.id,
                        'message': 'Vehicle created'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'Vehicle not created',
                        'message': 'data not created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class EditVehicleRegistration(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        try:
            serializer = EditVehicleRegistrationSerializer(data=request.data)
            if serializer.is_valid():
               
                vehicledata = vehicleinfo.objects.filter(id=serializer.data.get(
                        'vehicleinfoid', ''))
                if vehicledata:
                    # getdatauser = vehicleinfo.objects.get(id=serializer.data.get(
                    #     'vehicleinfoid', ''))
                    print("===========")
                    vehicledata.update( 
                        vehiclename=serializer.validated_data.get(
                            'vehiclename', ''),
                        maxorders=serializer.validated_data.get(
                            'maxorders', ''),
                        weightcapacity=serializer.validated_data.get(
                            'weightcapacity', ''),
                        phone=serializer.validated_data.get(
                            'phone', ''))
                    print("=========get data==", vehicledata)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'vehicleinfoid': 'Vehicle data update',
                        'message': 'Data updated successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Data not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class VehicleLogin(APIView):
    # permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = VehicleLoginSerializer(data=request.data)
            if serializer.is_valid():
                vehicleinfoid = serializer.data.get('vehicleinfoid')
                password = serializer.data.get('password')
                data = vehicleinfo.objects.filter(id=vehicleinfoid,password=password)
                print("---------",data)
                if data:
                    vehdata = vehicleinfo.objects.get(id=vehicleinfoid,password=password)
                    vehicledata={
                        'vechicleinfoid':vehdata.id,
                        'vehiclename':vehdata.vehiclename,
                        'maxorders':vehdata.maxorders,
                        'weightcapacity':vehdata.weightcapacity,
                        'phone':vehdata.phone,
                        'is_deleted':vehdata.is_deleted,
                        'created_at':vehdata.created_at,
                        'userid':vehdata.userid.id,
                    }
                    token= token = get_tokens_for_user(vehdata)

                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': vehicledata,
                        'refresh': str(token.get("refresh")),
                        'access': str(token.get("access")),
                        'message': 'Vehicle created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': '',
                        'message': 'Vehicleid or password not correct'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetVehicleDetail(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetVehicleDetailSerializer(data=request.data)
            if serializer.is_valid():
                vehicleinfoid = serializer.data.get('vehicleinfoid')
                data = vehicleinfo.objects.filter(id=vehicleinfoid)
                print("---------",data)
                if data:
                    vehdata = vehicleinfo.objects.get(id=vehicleinfoid)
                    vehicledata={
                        'vechicleinfoid':vehdata.id,
                        'vehiclename':vehdata.vehiclename,
                        'maxorders':vehdata.maxorders,
                        'weightcapacity':vehdata.weightcapacity,
                        'phone':vehdata.phone,
                        'password':vehdata.password,
                        'is_deleted':vehdata.is_deleted,
                        'created_at':vehdata.created_at,
                        'userid':vehdata.userid.id
                    }
                    
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': vehicledata,
                        'message': 'Vehicle found'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Vehicle not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteVehicle(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            serializer = GetVehicleDetailSerializer(data=request.data)
            if serializer.is_valid():
                vehicledata = vehicleinfo.objects.filter(id=serializer.data.get(
                        'vehicleinfoid', ''))
                if vehicledata:
                    print("===========")
                    vehicledata.update(is_deleted=1)
                    print("=========get data==", vehicledata)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'message': 'Vehicle deleted successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Vehicle not deleted'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
class VehicleList_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = GetVehicleListSerializer(data=request.data)
            if serializer.is_valid():
                print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', ''))
                if vehicledata:

                    vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                        'userid', ''))
                    print("=============",vehicleobj)
                    
                    vehiclelist = [{"id": data.id, "vehiclename": data.vehiclename, "phone": data.phone, 
                                    "maxorders": data.maxorders, "weightcapacity": data.weightcapacity, 'userid': data.userid.id,'created_at': data.created_at,'password': data.password} for data in vehicleobj]
                    print("---------",vehiclelist)
                    if vehicleobj :
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': vehiclelist,
                            'message': 'Vehicle found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        print("================")
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'Vehicle not found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                else:
                    print("================")
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddSlotInfo(APIView):
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = AddSlotSerializer(data=request.data)
            if serializer.is_valid():
                print("=======================")
                slotobj = slotinfo.objects.create(
                    userid=serializer.validated_data['userid'],
                    slottime=serializer.validated_data.get('slottime'),
                    is_deleted=0,
                    created_at=datetime.now()
                )
                slotobj.save()
                print("---------------",slotobj)
                if slotobj:
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'slotid': slotobj.id,
                        'message': 'Slot created'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'Slot not created',
                        'message': 'Slot not created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class EditSlotInfo(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        try:
            serializer = EditSlotSerializer(data=request.data)
            if serializer.is_valid():
                vehicledata = slotinfo.objects.filter(id=serializer.data.get(
                        'slotid', ''))
                print("======22222",vehicledata)
                if vehicledata:
                    # getdatauser = vehicleinfo.objects.get(id=serializer.data.get(
                    #     'vehicleinfoid', ''))
                    print("===========")
                    vehicledata.update( slottime=serializer.validated_data.get(
                            'slottime', ''))
                    print("=========get data==", vehicledata)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'vehicleinfoid': 'Slot data update',
                        'message': 'Data updated successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Data not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class SlotList_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', ''))
                if vehicledata:

                    vehicleobj = slotinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                        'userid', ''))
                    print("=============",vehicleobj)
                    
                    vehiclelist = [{"id": data.id, "slottime": data.slottime, 
                                     'userid': data.userid.id,'created_at': data.created_at,'is_deleted': data.is_deleted} for data in vehicleobj]
                    print("---------",vehiclelist)
                    if vehicleobj :
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': vehiclelist,
                            'message': 'Slot found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        print("================")
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'Slot not found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                else:
                    print("================")
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetSlotDetail(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetSlotDetailSerializer(data=request.data)
            if serializer.is_valid():
                slotinfoid = serializer.data.get('slotinfoid')
                data = slotinfo.objects.filter(id=slotinfoid)
                print("---------",data)
                if data:
                    slotdata = slotinfo.objects.get(id=slotinfoid)
                    vehicledata={
                        'slotinfoid':slotdata.id,
                        'slottime':slotdata.slottime,
                        'is_deleted':slotdata.is_deleted,
                        'created_at':slotdata.created_at,
                        'userid':slotdata.userid.id
                    }
                    
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': vehicledata,
                        'message': 'Slot found'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Slot not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteSlot(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            serializer = GetSlotDetailSerializer(data=request.data)
            if serializer.is_valid():
                slotdata = slotinfo.objects.filter(id=serializer.data.get(
                        'slotinfoid', ''))
                if slotdata:
                    print("===========")
                    slotdata.update(is_deleted=1)
                    print("=========get data==", slotdata)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'message': 'Slot deleted successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Slot not deleted'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddCoordinatesUser(APIView):
    permission_classes = [IsAuthenticated]
    # Add warehouse cordinates Post Reuqest
    def patch(self, request):
        try:
            serializer = AddcordinatesSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = User.objects.filter(id=serializer.data.get(
                        'userid', ''))
                print("======22222",usercordiantes)
                if usercordiantes:
                    print("===========")
                    usercordiantes.update(longitude=serializer.validated_data.get(
                            'longitude', ''),latitude=serializer.validated_data.get(
                            'latitude', ''),)
                    print("=========get data==", usercordiantes)
              
                if usercordiantes:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Coordinate updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Coordinate not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class FetchInvoiceData(APIView):
    permission_classes = [IsAuthenticated]
    # Add warehouse cordinates Post Reuqest
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = zohoaccount.objects.filter(userid=serializer.data.get(
                        'userid', ''))
                print("======22222",usercordiantes)
                if usercordiantes:
                    data=zohoaccount.objects.get(userid=serializer.data.get(
                        'userid', ''))
                    print("===========",data.refreshtoken)
                    parameters = {
                    # "refresh_token":data.refreshtoken,
                    "refresh_token":"1000.25a090d5c14fadc4b1084d05556d077e.289204add6d03719a38814aa6c917ac6",
                    # "client_id":data.clientid,
                    "client_id":'1000.6CUWGWRSYBPGDHV0DG1L27R4M51WHX',
                    # "client_secret":data.clientsecret,
                    "client_secret":'6d8f85d3802ba38fd768a37c608a0ac30acbf6e730',
                    # "redirect_uri":data.clientsecret,
                    "redirect_uri":'https://www.google.co.in',
                    "grant_type":"refresh_token",
                    }
 
                    response = requests.post("https://accounts.zoho.in/oauth/v2/token?", params=parameters)
                    if response.status_code == 200:
                        data =   response.json()
                        accesstoken = data['access_token']
                        print("------",accesstoken)
                        currentdate=datetime.now().date()
                        currentdate='2022-10-31'
                        headers = {
                        'Content-Type':'application/json',
                        'Authorization':'Zoho-oauthtoken ' + str(accesstoken)
                                }

                        response = requests.get("https://books.zoho.in/api/v3/invoices?date_start={}".format(currentdate), headers=headers)
                        if response.status_code == 200:
                            data1 = response.json()
                            invoices=data1.get("invoices")
                            for invoice in invoices:
                                print("000000000000000000000000000000000000000000",invoice.get('invoice_id'))
                                response = requests.get("https://books.zoho.in/api/v3/invoices/{}".format(invoice.get('invoice_id')), headers=headers)
                                # print(".......",response.json())
                                
                            
                                for item in response.json().get("invoice").get("line_items"):

                                    getweight = iteminfo.objects.filter(zoho_item_id=item.get("item_id"))
                                    print("22222222222222222    ",getweight)
                                    if getweight:
                                        print("---------111111111111 ",getweight)

                                        getweightdata = iteminfo.objects.get(zoho_item_id=item.get("item_id"))
                                        chekuserobj = User.objects.filter(id=serializer.data.get('userid', ''))
                                        if chekuserobj:
                                            userobj = User.objects.get(id=serializer.data.get('userid', ''))
                                            print("=================",getweightdata.item_waight)
                                            orderobj=orderinfo.objects.filter(invoice_id=invoice.get('invoice_id',''))
                                            print("###############        ",orderobj)
                                            if not orderobj:
                                                print("------------------->>>>>>>>>>>>>>>>>>>>>>>>>")
                                                bool_value=0
                                                if checkcoordinate(s=invoice.get("cf_location_coordinate")):
                                                    bool_value=1
                                                vehicledata=orderinfo.objects.create(
                                                    userid=userobj,
                                                    shipping_address=invoice.get("shipping_address").get("address"),
                                                    invoice_id=invoice.get("invoice_id"),
                                                    customer_id=invoice.get("customer_id"),
                                                    weight=getweightdata.item_waight,
                                                    customer_name=invoice.get("customer_name"),
                                                    invoice_number=invoice.get("invoice_number"),
                                                    invoice_total=invoice.get("total"),
                                                    invoice_balance=invoice.get("balance"),
                                                    time_slot=invoice.get("cf_time_slots"),
                                                    contactno=invoice.get("shipping_address").get("phone"),
                                                    location_coordinates=invoice.get("cf_location_coordinate"),
                                                    is_coordinate=bool_value,
                                                    is_deleted=0,
                                                    updated_at=datetime.now(),
                                                    created_date=datetime.now()#this date change by zoho created_time
                                                )
                                                vehicledata.save()

                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'status': data1,
                            'data222222222': response.json().get("invoice").get("line_items"),
                            'message': 'Coordinate updated'
                            }
                        return Response(json_data, status.HTTP_200_OK)
                    
                    
                    print("=========get data==", usercordiantes)

              
                if usercordiantes:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Coordinate updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Coordinate not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class AddItemAPI(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = zohoaccount.objects.filter(userid=serializer.data.get(
                        'userid', ''))
                print("======22222",usercordiantes)
                if usercordiantes:
                    data=zohoaccount.objects.get(userid=serializer.data.get(
                        'userid', ''))
                    print("===========",data.refreshtoken)
                    parameters = {
                    # "refresh_token":data.refreshtoken,
                    "refresh_token":"1000.25a090d5c14fadc4b1084d05556d077e.289204add6d03719a38814aa6c917ac6",
                    # "client_id":data.clientid,
                    "client_id":'1000.6CUWGWRSYBPGDHV0DG1L27R4M51WHX',
                    # "client_secret":data.clientsecret,
                    "client_secret":'6d8f85d3802ba38fd768a37c608a0ac30acbf6e730',
                    # "redirect_uri":data.redirecturi,
                    "redirect_uri":'https://www.google.co.in',
                    "grant_type":"refresh_token",
                    }

                    response = requests.post("https://accounts.zoho.in/oauth/v2/token?", params=parameters)
                    if response.status_code == 200:
                        data =   response.json()
                        accesstoken = data['access_token']
                        print("dddddddd ",accesstoken)

                        headers = {
                            'Content-Type':'application/json',
                            'Authorization':'Zoho-oauthtoken ' + str(accesstoken)
                            }
                        
                        response = requests.get("https://books.zoho.in/api/v3/items", headers=headers)
                        print("llll ",response)
                        if response.status_code == 200:
                            data =   response.json()
                            # print(";;;;;;; ",data)
                            for d in data.get("items"):
                                # check item id
                                already=iteminfo.objects.filter(zoho_item_id=d.get('item_id', ''))
                                userid=User.objects.get(id=serializer.data.get('userid'))
                                if not already:
                                    zohodata = iteminfo.objects.create(
                                        userid=userid,
                                        zoho_item_id=d.get('item_id'),
                                        item_name=d.get('name'),
                                        item_waight=0,
                                        created_at=datetime.now(),
                                        is_deleted=0,
                                        updated_at=datetime.now(),
                                    )
                                    zohodata.save()
                                else:print('Else')
                            
                            json_data = {
                                'status_code': 201,
                                'status': 'Success',
                                'data':data,
                                'message': 'User created'
                            }
                            return Response(json_data, status.HTTP_201_CREATED)



                # user.set_password(serializer.validated_data['password'])
                # user.save()
                # refresh = RefreshToken.for_user(user)
                if 'user':
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        
                        'message': 'User created'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'User not created',
                        'message': 'data not created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 200,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class ItemList_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', ''))
                if vehicledata:

                    vehicleobj = iteminfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                        'userid', '')).order_by('item_waight')
                    # print("=============",vehicleobj)
                    
                    vehiclelist = [{"id": data.id, "zoho_item_id": data.zoho_item_id, 
                                     'userid': data.userid.id,'created_at': data.created_at,'item_name': data.item_name,'item_waight': data.item_waight,'is_deleted': data.is_deleted} for data in vehicleobj]
                    # print("---------",vehiclelist)
                    if vehicleobj :
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': vehiclelist,
                            'message': 'Item found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        print("================")
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'Item not found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                else:
                    print("================")
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetItemDetail(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetItemDetailSerializer(data=request.data)
            if serializer.is_valid():
                iteminfoid = serializer.data.get('iteminfoid')
                data = iteminfo.objects.filter(id=iteminfoid)
                print("---------",data)
                if data:
                    slotdata = iteminfo.objects.get(id=iteminfoid)
                    vehicledata={
                        'iteminfoid':slotdata.id,
                        'zoho_item_id':slotdata.zoho_item_id,
                        'item_name':slotdata.item_name,
                        'item_waight':slotdata.item_waight,
                        'created_at':slotdata.created_at,
                        'is_deleted':slotdata.is_deleted,
                        'updated_at':slotdata.updated_at,
                        'userid':slotdata.userid.id
                    }
                  
                    
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': vehicledata,
                        'message': 'Item found'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Item not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class EditItemInfo(APIView):
    # Handling Post Reuqest
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        try:
            serializer = EditItemDetailSerializer(data=request.data)
            if serializer.is_valid():
               
                vehicledata = iteminfo.objects.filter(id=serializer.data.get(
                        'iteminfoid', ''))
                if vehicledata:
                    # getdatauser = vehicleinfo.objects.get(id=serializer.data.get(
                    #     'vehicleinfoid', ''))
                    print("===========")
                    vehicledata.update( 
                        item_waight=serializer.validated_data.get(
                            'item_waight', ''))
                    print("=========get data==", vehicledata)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'data': 'Item data update',
                        'message': 'Data updated successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Data not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetOrderbySlotDetail(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetOrderbySlotDetailSerializer(data=request.data)
            if serializer.is_valid():
                userid = serializer.data.get('userid')
                datacheck=User.objects.filter(id=userid)
                #Check Data 
                if datacheck:
                    #Getting data of user
                    # data = User.objects.get(id=userid)
                    slotidid = serializer.data.get('slotid')
                    data = slotinfo.objects.filter(id=slotidid)
                    print("---------",data)
                    if data:
                        print("++++++++++++++++++++")
                        slotdata = slotinfo.objects.filter(id=slotidid,userid=userid)
                        print("888888888 ",slotdata)
                        if slotdata:
                            slotinfodata = slotinfo.objects.get(id=slotidid,userid=userid)
                            totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime)
                            orderwithoutcoordinates = orderinfo.objects.filter(time_slot=slotinfodata.slottime,location_coordinates='')
                            orderwithcoordinats=len(totalorders)-len(orderwithoutcoordinates)
                            vehicledata={
                                'totalorders':len(totalorders),
                                'orderwithoutcoordinates':len(orderwithoutcoordinates),
                                'orderwithcoordinats':orderwithcoordinats,
                            }
                            print("-----------",slotinfodata.slottime)
                    
                    
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': vehicledata,
                            'message': 'Item found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'data': '',
                            'message': 'Slot not found'
                        }
                        return Response(json_data, status.HTTP_204_NO_CONTENT)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Item not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

from .route_optimisation_capacity_weight import generate_optimised_way as gow
from .route_optimisation_capacity_weight import optimisation
from .distance_matrix import distance_matrix
class RootOptimazationAPI(APIView):
    # permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetOrderbySlotDetailSerializer(data=request.data)
            if serializer.is_valid():
                userid = serializer.data.get('userid')
                datacheck=User.objects.filter(id=userid)
                #Check Data 
                if datacheck:
                    #Getting data of user
                    # data = User.objects.get(id=userid)
                    slotidid = serializer.data.get('slotid')
                    data = slotinfo.objects.filter(id=slotidid)
                    print("---------",data)
                    if data:
                        print("++++++++++++++++++++")
                        slotdata = slotinfo.objects.filter(id=slotidid,userid=userid)
                        print("888888888 ",slotdata)
                        if slotdata:
                            slotinfodata = slotinfo.objects.get(id=slotidid,userid=userid)
                            vehicledata = vehicleinfo.objects.filter(userid=userid,is_deleted=0)
                            vehiclenamelist=[data.vehiclename for data in vehicledata]
                            vehicleweightlist=[int(data.weightcapacity) for data in vehicledata]
                            vehiclemaxorderlist=[int(data.maxorders) for data in vehicledata]
                            print("77777777   ",vehiclenamelist)
                            print("777777778   ",vehicleweightlist)
                            print("777777779   ",vehiclemaxorderlist)
                            vehicledatainfo=[]
                            # print("55555555      ",slotinfodata.userid.longitude,slotinfodata.userid.latitude)
                            print("55555555      ",vehicledata)
                            totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime)
                            order_with_coordinate = orderinfo.objects.filter(time_slot=slotinfodata.slottime,location_coordinates__isnull=False,is_coordinate=1)#Add in condition ,created_date=datetime.now()
                            # orderwithcoordinats=len(totalorders)-len(orderwithoutcoordinates)
                            print("0000000000     ",order_with_coordinate)
                            vehicledata={
                                'totalorders':len(totalorders),
                                'orderwithoutcoordinates':'',
                                'orderwithcoordinats':'',
                            }
                            print("-----------",slotinfodata.slottime)
                            final_data={'shipping_address':['none'],
                            'invoice_id':['none'],
                            'customer_id':['none'],
                            'customer_name':['WareHouse'],
                            'invoice_number':['none'],
                            'invoice_total':[0],
                            'invoice_balance':[0],
                            'time_slot':['none'],
                            'location_coordinates':[" ".join([slotinfodata.userid.latitude,slotinfodata.userid.longitude])],
                            'weight':[0],
                            'created_date':['none'],
                            'contactno':['none']

                                }
                            for data in list(order_with_coordinate):
                                final_data['shipping_address'].append(data.shipping_address), 
                                final_data['invoice_id'].append(data.invoice_id),
                                final_data['customer_id'].append(data.customer_id),
                                final_data['customer_name'].append(data.customer_name), 
                                final_data['invoice_number'].append(data.invoice_number), 
                                final_data['invoice_total'].append(data.invoice_total), 
                                final_data['invoice_balance'].append(data.invoice_balance), 
                                final_data['time_slot'].append(data.time_slot), 
                                final_data['location_coordinates'].append(data.location_coordinates), 
                                final_data['weight'].append(data.weight), 
                                final_data['created_date'].append(data.created_date), 
                                final_data['contactno'].append(data.contactno), 
                            print("kkkkkkk ",final_data)
                            coords=final_data['location_coordinates']
                            location_weights=final_data['weight']
                            location_names=final_data['customer_name']
                            print("77777777   ",vehiclenamelist)
                            print("777777778   ",vehicleweightlist)
                            print("777777779   ",vehiclemaxorderlist)
                            vehicle_wt_capacities=vehicleweightlist
                            vehicle_order_capcity=vehiclemaxorderlist
                            vehicle_names=vehiclenamelist
                            due_amount=final_data['invoice_balance']
                            phone_number=final_data['contactno']
                            invoice_number=final_data['invoice_number']
                            print('hfhfkvv')
                            print(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,location_names,)
                            # k=gow(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,location_names,  depot=0)

                            data_locations =gow(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,location_names, due_amount,phone_number,invoice_number, depot=0)
                            final_data=[]
                            for key in data_locations.keys():
                                entry={}
                                entry['vehicle_name']=key
                                entry['data']=[]
                                for order in data_locations[key][0]:
                                    obj={}
                                    obj['customername']=order[0]
                                    obj['Contact']=order[1]
                                    obj['Coordinates']=order[2]
                                    obj['DueAmount']=order[3]
                                    entry['data'].append(obj)
                                    # entry.append(obj)
                                final_data.append(entry)
                            print("111111111111111111111",final_data)
                            print(data_locations)
                            for obj in data_locations:
                                print("kkkkkkkkkkkk   ",obj)
                                # root_data={
                                #     'Name':obj[0],
                                #     'Contact':obj[2],
                                #     'Coordinates':obj[3],
                                #     'DueAmount':obj[1]
                                # }
                                # final_data.append(root_data)
                            json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': final_data,
                            'message': 'Item found'
                            }
                            return Response(json_data, status.HTTP_200_OK)   
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': root_data,
                            'message': 'Item found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'data': '',
                            'message': 'Slot not found'
                        }
                        return Response(json_data, status.HTTP_204_NO_CONTENT)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Item not found'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
