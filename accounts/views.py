from django.shortcuts import render
from ast import Try
import imp
# from .distance_matrix import  coordinates_preprocesing
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
import ast
from django.utils import timezone
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
                branch_id = serializer.validated_data.get('branch_id')
                user = User.objects.create(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    first_name=serializer.validated_data.get('first_name', ''),
                    last_name=serializer.validated_data.get('last_name', ''),
                    mobile=serializer.validated_data.get('mobile', ''),
                    branch_id=branch_id,
                    is_zoho_active=1
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
                    # print("-----------------", newdata)
                    # print("-----------------", type(data))
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
                zohocredentialid=zohoaccount.objects.filter(userid=serializer.data.get('userid'))
                if zohocredentialid:
                    zohodata=zohoaccount.objects.get(userid=serializer.data.get('userid'))
                    zohocredentialid.update(
                    clientid='',
                    clientsecret='',
                    accesstoken='',
                    refreshtoken='',
                    redirecturi=''
                    )
                else:    
                    # print("---llll ",userid)
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
                                                       https://www.onlinethela.online/add-credential?id="""+str(zohodata.id)+""""
                                                        <strong>Redirect URL</strong>
                                                       https://www.onlinethela.online/add-access
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
                'error': f'{err}',
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
            # print("------",datacheck)
            #Check Data 
            if datacheck:
                #Getting data of user
                data = User.objects.get(id=request.data.get("id") if request.data.get("id") else 0)
                # print("==========",data)
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
                'error': f'{err}',
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
                    # print("=========get data==", datauser)
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

                userid = serializer.data.get('userid')
                datacheck=zohoaccount.objects.filter(userid=userid)
                print("------",datacheck)
                #Check Data 
                if datacheck:
                    #Getting data of user
                    data = zohoaccount.objects.get(userid=userid)
                    print("==========",data)
                    newdata = {
                        "zohoaccountid": data.id,
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
                'error': f'{err}',
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
                    emailBody = "UnOrg code : "+str(getdatauser.id)+"<br>https://accounts.zoho.com/oauth/v2/auth?scope=ZohoBooks.invoices.CREATE,ZohoBooks.fullaccess.all,ZohoBooks.invoices.READ,ZohoBooks.invoices.UPDATE,ZohoBooks.invoices.DELETE&client_id=" + \
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
                    data = ordersdelivery.objects.filter(is_manually_assigned=1,is_deleted=0,user_id=serializer.data.get('userid', ''))
                    list_of_data=[]
                    for d in data:
                        print(d)
                        d_value=d.vehicle_id_id
                        if d_value not in list_of_data:
                            list_of_data.append(d_value)
                    vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                        'userid', '')).exclude(id__in=list_of_data)
                    from django.db.models import OuterRef, Subquery
                    # ordersdelivery = ordersdelivery.objects.exclude(is_manually_assigned=0,vehicle_id=vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                                        # 'userid', ''),is_vehicle_not_available=0))
                    
                    # print("=============",vehicleobj)
                    vehiclelist=[]
                    for data in vehicleobj:
                        totalvehicle_remaining_weight=0
                        for delivery_order in ordersdelivery.objects.filter(vehicle_id=data.id,user_id=data.userid.id,is_deleted=0):
                            totalvehicle_remaining_weight+=delivery_order.weight
                        datadict={
                            "id": data.id,
                            "vehiclename": data.vehiclename,
                            "phone": data.phone,
                            "maxorders": data.maxorders,
                            "weightcapacity": data.weightcapacity,
                            'userid': data.userid.id,
                            'created_at': data.created_at,
                            'password': data.password,
                            'vehicle_remaining_weight': int(data.weightcapacity)-totalvehicle_remaining_weight
                        }
                        vehiclelist.append(datadict)

                    
                    # vehiclelist = [{"id": data.id,
                    # "vehiclename": data.vehiclename,
                    # "phone": data.phone,
                    # "remainingweight": [ delivery_order.weight for delivery_order in ordersdelivery.objects.filter(vehicle_id=data.id,user_id=data.userid.id,is_deleted=0)], 

                    # "maxorders": data.maxorders,
                    # "weightcapacity": data.weightcapacity,
                    # 'userid': data.userid.id,
                    # 'created_at': data.created_at,
                    # 'password': data.password}
                    #  for data in vehicleobj]
                    # print("---------",vehiclelist)
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
                'error': f'{err}',
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
    # permission_classes = [IsAuthenticated]
    # Add warehouse cordinates Post Reuqest
    def post(self, request):
        try:
            req = requests.Session()
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = zohoaccount.objects.filter(userid=serializer.data.get(
                        'userid', ''))
                if usercordiantes:
                    # data=zohoaccount.objects.get(userid=serializer.data.get(
                    #     'userid', ''))
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
 
                    response = req.post("https://accounts.zoho.in/oauth/v2/token?", params=parameters)
                    if response.status_code == 200:
                        data =   response.json()
                        accesstoken = data['access_token']
                        currentdate=datetime.now().date()
                        currentdate='2022-10-31'
                        headers = {
                        'Content-Type':'application/json',
                        'Authorization':'Zoho-oauthtoken ' + str(accesstoken)
                                }

                        response = req.get("https://books.zoho.in/api/v3/invoices?date_start={}".format(currentdate), headers=headers)
                        if response.status_code == 200:
                            data1 = response.json()
                            invoices=data1.get("invoices")
                            for invoice in invoices:
                                response = req.get("https://books.zoho.in/api/v3/invoices/{}".format(invoice.get('invoice_id')), headers=headers)
                                # print(".......",response.json())
                                
                            
                                for item in response.json().get("invoice").get("line_items"):
                                    
                                    getweight = iteminfo.objects.filter(zoho_item_id=item.get("item_id"),userid=serializer.data.get(
                        'userid', ''))
                                    if getweight:

                                        getweightdata = iteminfo.objects.get(zoho_item_id=item.get("item_id"),userid=serializer.data.get(
                        'userid', ''))
                                        chekuserobj = User.objects.filter(id=serializer.data.get('userid', ''))
                                        if chekuserobj:
                                            userobj = User.objects.get(id=serializer.data.get('userid', ''))
                                            orderobj=orderinfo.objects.filter(invoice_id=invoice.get('invoice_id',''),userid=serializer.data.get('userid', ''))
                                            if not orderobj:
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
                            # 'status': "s",
                            'data222222222': "done data",
                            'message': 'Coordinate updated'
                            }
                        return Response(json_data, status.HTTP_200_OK)
                    
                    

              
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class AddItemAPI(APIView):
    # permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = zohoaccount.objects.filter(userid=serializer.data.get(
                        'userid', ''),is_deleted=0).exists()
                print("======22222",usercordiantes)
                if usercordiantes:
                    # data=zohoaccount.objects.get(userid=serializer.data.get(
                    #     'userid', ''),is_deleted=0)
                    # print("===========",data.refreshtoken)
                    parameters = {
                    # "refresh_token":data.refreshtoken,
                    # "refresh_token":"1000.25a090d5c14fadc4b1084d05556d077e.289204add6d03719a38814aa6c917ac6",
                    "refresh_token":"1000.18dbbc8aeb1c86231d317882035fd4ba.6fb716064eb7baa1ca994b80faa337cb",
                    # "client_id":data.clientid,
                    # "client_id":'1000.6CUWGWRSYBPGDHV0DG1L27R4M51WHX',
                    "client_id":'1000.KNTTWIQG6BRID6XQGEURG025O51XXD',
                    # "client_secret":data.clientsecret,
                    # "client_secret":'6d8f85d3802ba38fd768a37c608a0ac30acbf6e730',
                    "client_secret":'c7a0541ea8b37ea7716dc368d393fdab5f11891ae1',
                    # "redirect_uri":data.redirecturi,
                    "redirect_uri":'https://www.onlinethela.online/add-access',
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
                            message='Iitem not found'
                            # print(";;;;;;; ",data)
                            for d in data.get("items"):
                                message='All items already exist'
                                # check item id
                                already=iteminfo.objects.filter(zoho_item_id=d.get('item_id', ''),userid=serializer.data.get('userid'))
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
                                    message="Items updated"
                                
                            
                            json_data = {
                                'status_code': 201,
                                'status': 'Success',
                                'data':'',
                                'message': message
                            }
                            return Response(json_data, status.HTTP_201_CREATED)
                        else:
                            json_data = {
                                    'status_code': 400,
                                    'status': 'Success',
                                    'data':'',
                                    'message': "{}".format(response)
                                }
                            return Response(json_data, status.HTTP_400_BAD_REQUEST)
                    else:
                            json_data = {
                                    'status_code': 400,
                                    'status': 'Success',
                                    'data':'',
                                    'message': "{}".format(response)
                                }
                            return Response(json_data, status.HTTP_400_BAD_REQUEST)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'User not found',
                        'message': 'data not found'
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
                'error': "{}".format(err),
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

                    vehicleobj = iteminfo.objects.filter(is_deleted=0,userid=serializer.data.get('userid', '')).order_by('item_waight')
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
                        slotdata = slotinfo.objects.filter(id=slotidid,userid=userid)#userid=userid
                        print("888888888 ",slotdata)
                        checkorder_weight_msg=''
                        if slotdata:
                            vehiclelist=vehicleinfo.objects.filter(userid=userid,is_deleted=0)
                            totalvehicleweight=0
                            for vehicle in vehiclelist:
                                totalvehicleweight+=int(vehicle.weightcapacity)
                            print(len(vehiclelist),"-------Total vehicle weight------",totalvehicleweight)
                            average_vehicle_calculated_weight=totalvehicleweight/len(vehiclelist)
                            # vehiclelist=orderinfo.objects.filter(userid=userid)
                            slotinfodata = slotinfo.objects.get(id=slotidid,userid=userid)#userid=userid
                            # ____Exclude Those order that are not assgined
                            data_pop = ordersdelivery.objects.filter(time_slot=slotinfodata.slottime,user_id=serializer.data.get('userid'))
                            # order_with_coordinate = list(order_with_coordinate)
                            invoice_id=[]
                            for data in data_pop:
                                try:
                                    invoice_id.append(data.invoice_id)
                                    print("gotcha")
                                except Exception as e:
                                    print(e)
                                    pass
                            
                            created_date = datetime.now().date()
                            created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                            # totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime,userid=userid).exclude(invoice_id__in=invoice_id)
                            orderwithoutcoordinates = orderinfo.objects.filter(created_date__date = created_date,time_slot=slotinfodata.slottime,is_coordinate=0,userid=userid).exclude(invoice_id__in=invoice_id)
                            orderwithcoordinates = orderinfo.objects.filter(created_date__date = created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=userid,is_deleted=0,weight__lt=average_vehicle_calculated_weight).exclude(invoice_id__in=invoice_id)
                            #Getting Extra Order weight
                            manual_count = ordersdelivery.objects.filter(created_date__date = created_date,is_manually_assigned=1,is_deleted=0,user_id=serializer.data.get('userid', ''),time_slot=slotinfodata.slottime).count()
                            orderwithoutexceeded = orderinfo.objects.filter(created_date__date = created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=userid,weight__gt=average_vehicle_calculated_weight,is_deleted=0).exclude(invoice_id__in=invoice_id)
                            # print("----Exceeded Order List >>>> ----- ",orderwithoutexceeded)
                            allorderlist = orderinfo.objects.filter(created_date__date = created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=userid,is_deleted=0)
                            total_orders_weight=0
                            for orderdata in allorderlist:
                                total_orders_weight+=orderdata.weight
                            print("Averate orders weight------>  ",total_orders_weight)
                            totalorders=len(orderwithoutcoordinates)+len(orderwithcoordinates)+len(orderwithoutexceeded)+manual_count
                            # print("----Exceeded Order List >>>> ----- ",len(orderwithoutexceeded))
                            vehicledata={
                                'totalorders':totalorders,
                                'orderwithoutcoordinates':len(orderwithoutcoordinates),
                                'orderwithcoordinats':len(orderwithcoordinates),
                                'orderweightexceededvehicleweight':len(orderwithoutexceeded),
                                'manual_count':manual_count
                            }
                            print(average_vehicle_calculated_weight," Total Orders weight",total_orders_weight)
                            if total_orders_weight>totalvehicleweight:
                                checkorder_weight_msg='Orders weight is greater than vehicle weight capacity.Please Add more vehicle'
                            # print("-----------",slotinfodata.slottime)
                    
                    
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': vehicledata,
                            'message': 'Item found',
                            'checkorder_weight_msg':checkorder_weight_msg
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

from .route_optimisation_capacity_weight import generate_optimised_way as gow
from .route_optimisation_capacity_weight import optimisation
from .distance_matrix import distance_matrix
from .rootoptgraph import plot_vehicle_graph as pltgraph
class RootOptimazationAPI(APIView):
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
                    # Delete Data from Order Delivery Table Of Specific WareHouse-------------
                    
                    slotidid = serializer.data.get('slotid')
                    data = slotinfo.objects.filter(id=slotidid)
                    if data:
                        created_date = datetime.now().date()
                        created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                      
                        slotdata = slotinfo.objects.filter(id=slotidid,userid=userid)
                        if slotdata:
                            slotinfodata = slotinfo.objects.get(id=slotidid,userid=userid)
                            deletewaredata=ordersdelivery.objects.filter(user_id=userid,time_slot=slotinfodata.slottime,is_manually_assigned=0)
                            if deletewaredata:
                                deletewaredata.update(is_deleted=1)
                            vehicledata = vehicleinfo.objects.filter(userid=userid,is_deleted=0,is_vehicle_not_available=0)
                            vehiclenamelist=[data.vehiclename for data in vehicledata]
                            vehicleidlist=[data.id for data in vehicledata]
                            vehicleweightlist=[int(data.weightcapacity) for data in vehicledata]
                            vehiclemaxorderlist=[int(data.maxorders) for data in vehicledata]
                            vehicledatainfo=[]
                            if vehicledata:
                                pass
                            else:
                                json_data = {
                                'status_code': 500,
                                'status': 'Success',
                                'message': 'Vehicle not available'
                                }
                                return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
                            # print("---Vehicle id list : ",vehicleidlist)
                            # print("---Vehicle name list : ",vehiclenamelist)
                            # print("---Vehicle weight list : ",len(vehicleweightlist))
                            # print("---Vehicle maxorder list : ",len(vehiclemaxorderlist))
                            vehiclelist=vehicleinfo.objects.filter(userid=userid,is_deleted=0)
                            averagevehicleweight=0
                            for vehicle in vehiclelist:
                                averagevehicleweight+=int(vehicle.weightcapacity)
                                # print(len(vehiclelist),"-------2222------",vehicle.weightcapacity)
                            average_vehicle_calculated_weight=averagevehicleweight/len(vehiclelist)
                            # print("55555555      ",slotinfodata.userid.longitude,slotinfodata.userid.latitude)
                            # totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime,userid=serializer.data.get('userid'),is_deleted=0)
                            # order_with_coordinate = orderinfo.objects.filter(time_slot=slotinfodata.slottime,location_coordinates__isnull=False,is_coordinate=1)#Add in condition ,created_date=datetime.now()
                            # order_with_coordinate = orderinfo.objects.filter(time_slot=slotinfodata.slottime,is_coordinate=1,userid=serializer.data.get('userid'),is_deleted=0,weight__lt=average_vehicle_calculated_weight)#Add in condition ,created_date=datetime.now()
                            data_pop = ordersdelivery.objects.filter(time_slot=slotinfodata.slottime,user_id=serializer.data.get('userid'))
                            # order_with_coordinate = list(order_with_coordinate)
                            invoice_id=[]
                            for data in data_pop:
                                try:
                                    invoice_id.append(data.invoice_id)
                                    print("gotcha")
                                except Exception as e:
                                    print(e)
                                    pass
                            order_with_coordinate = orderinfo.objects.filter(created_date__date=created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=serializer.data.get('userid'),is_deleted=0,weight__lt=average_vehicle_calculated_weight).exclude(invoice_id__in=invoice_id)
                            print("----order_with_coordinate length : ",len(order_with_coordinate))
                            # orderwithcoordinats=len(totalorders)-len(orderwithoutcoordinates)
                            # vehicledata={
                            #     'totalorders':len(totalorders),
                            #     'orderwithoutcoordinates':'',
                            #     'orderwithcoordinats':'',
                            # }
                            # print("=++++++++    ",order_with_coordinate)
                            final_data={'shipping_address':['none'],
                            'invoice_id':['none'],
                            'order_id':['none'],
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
                            orderidlist=[]
                            for data in list(order_with_coordinate):
                                orderidlist.append(data.id)
                                final_data['shipping_address'].append(data.shipping_address),  
                                final_data['invoice_id'].append(data.invoice_id),
                                final_data['order_id'].append(data.id),
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
                            coords=final_data['location_coordinates']
                            location_weights=final_data['weight']
                            location_names=final_data['customer_name']
                            vehicle_wt_capacities=vehicleweightlist
                            vehicle_order_capcity=vehiclemaxorderlist
                            vehicle_names=vehiclenamelist
                            due_amount=final_data['invoice_balance']
                            phone_number=final_data['contactno']
                            invoice_number=final_data['invoice_number']
                            #Additional Feilds-------------
                            invoiceidlist=final_data['invoice_id']
                            orderidlist=final_data['order_id']
                            useridlist=[userid]

                            # print("))))))))    ",vehicle_wt_capacities,vehicle_order_capcity,vehicle_names)
                            # k=gow(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,location_names,  depot=0)

                            data_locations =gow(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,vehicleidlist,location_names, due_amount,phone_number,invoice_number,invoiceidlist,orderidlist, depot=0)
                            # print("===========>>>>> ",data_locations)
                            final_data=[]
                            for key in data_locations.keys():
                                entry={}
                                entry['vehicle_id']=key
                                entry['vehicle_name']=data_locations[key][0][0][6]
                                entry['data']=[]
                                for order in data_locations[key][0]:
                                    obj={}
                                    obj['customername']=order[0]
                                    obj['Contact']=order[2]
                                    obj['Coordinates']=order[4]
                                    obj['DueAmount']=order[1]
                                    obj['invoice_id']=order[5]
                                    obj['vehicle_name']=order[6]
                                    obj['weight']=order[7]
                                    obj['orderid']=order[8]
                                    entry['data'].append(obj)
                                    # entry.append(obj)
                                final_data.append(entry)
                            
                            for assignorder in final_data:
                                # print("Hey I am data of one vehicle : ===========  ",assignorder)
                                vehicle_id = assignorder.get("vehicle_id")
                                print("Vehicle Id is : ",vehicle_id)
                                serial_num=1
                                for orderdata in assignorder.get("data"):
                                    invoice_id=orderdata.get("invoice_id")
                                    orderinfodata= orderinfo.objects.get(userid=userid,invoice_id=invoice_id,is_deleted=0) if orderinfo.objects.filter(userid=userid,invoice_id=invoice_id,is_deleted=0).exists() else 0
                                    # print(serial_num,"-------++++++++++-------",type(orderinfodata))
                                    if orderinfodata:
                                        # print(serial_num,"-------++++++++++-------",orderinfodata.weight)
                                   
                                        checkorderdelivery=ordersdelivery.objects.filter(invoice_id=invoice_id,vehicle_id=vehicle_id,user_id=userid,is_deleted=0)
                                        if not checkorderdelivery:
                                            vehicleobj=vehicleinfo.objects.get(id=vehicle_id,userid=userid,is_deleted=0)
                                            userobj=User.objects.get(id=userid)
                                            
                                            # print("--------",orderinfodata)
                                            orderdata=ordersdelivery.objects.create(
                                                order_id=orderinfodata,
                                                vehicle_id=vehicleobj,
                                                time_slot=orderinfodata.time_slot,
                                                user_id=userobj,
                                                customer_name=orderinfodata.customer_name,
                                                phone_number=orderinfodata.contactno,
                                                email='',
                                                location_coordinates=orderinfodata.location_coordinates,
                                                location_url=orderinfodata.location_url,
                                                weight=orderinfodata.weight,
                                                serialno=serial_num,
                                                shipping_address=orderinfodata.shipping_address,
                                                collectedAmount=0,
                                                invoice_total=orderinfodata.invoice_total,
                                                invoice_balance=orderinfodata.invoice_balance,
                                                invoice_number=orderinfodata.invoice_number,
                                                invoice_id=orderinfodata.invoice_id,
                                                status='Pending',
                                                upi=0,
                                                cash=0,
                                                other=0,
                                                reason='',
                                                is_deleted=0,
                                                is_published=0,
                                                updated_at=datetime.now(),
                                                created_date=datetime.now()
                                            )
                                            orderdata.save()
                                            vehicleobj.is_vehicle_not_available=1
                                            vehicleobj.save()
                                        else:
                                            print("Else condition----------- ")
                                        
                                        serial_num+=1
                            graphurl=pltgraph(final_data)
                            graph_image_url='https://www.onlinethela.online/static/warehouses_graph/'+graphurl
                            json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': final_data,
                            'graph_url': graph_image_url,
                            'message': 'Item found'
                            }
                            return Response(json_data, status.HTTP_200_OK)   
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': final_data,
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class GetOrderwithCoordinatesList(APIView):
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
                            # totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime)
                            orderwithoutcoordinates = orderinfo.objects.filter(time_slot=slotinfodata.slottime,is_coordinate=1)

                            orderlist = [{"id": data.id, "shipping_address": data.shipping_address, 
                            "invoice_id": data.invoice_id, 
                            "customer_name": data.customer_name, 
                            "invoice_number": data.invoice_number, 
                            "invoice_total": data.invoice_total, 
                            "invoice_balance": data.invoice_balance, 
                            "time_slot": data.time_slot, 
                            "contactno": data.contactno, 
                            "location_coordinates": data.location_coordinates, 
                            "is_coordinated": data.is_coordinate, 
                            "is_deleted": data.is_deleted, 
                            "updated_at": data.updated_at, 
                                            "customer_id": data.customer_id, "weight": data.weight, 'userid': data.userid.id,'created_date': data.created_date} for data in orderwithoutcoordinates]
                            # print("---------",vehiclelist)
                           
                    
                    
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': orderlist,
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



class GetOrderwithoutCoordinatesList(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetOrderbyfororderListSlotDetailSerializer(data=request.data)
            if serializer.is_valid():
                userid = serializer.data.get('userid')
                datacheck=User.objects.filter(id=userid)
                coordinate_type=serializer.data.get('coordinate_type')
                #Check Data 
                if datacheck:
                    #Getting data of user
                    # data = User.objects.get(id=userid)
                    slotidid = serializer.data.get('slotid')
                    data = slotinfo.objects.filter(id=slotidid)
                    print("---------",data)
                    if data:
                        orderlist=[]
                        print("++++++++++++++++++++")
                        slotdata = slotinfo.objects.filter(id=slotidid,userid=userid)
                        # print("888888888 ",slotdata)
                        if slotdata:
                            slotinfodata = slotinfo.objects.get(id=slotidid,userid=userid)
                            print("Inside the second elif")
                            vehiclelist=vehicleinfo.objects.filter(userid=userid,is_deleted=0)
                            averagevehicleweight=0
                            for vehicle in vehiclelist:
                                averagevehicleweight+=int(vehicle.weightcapacity)
                                # print(len(vehiclelist),"-------2222------",vehicle.weightcapacity)
                            average_vehicle_calculated_weight=averagevehicleweight/len(vehiclelist)
                            # totalorders = orderinfo.objects.filter(time_slot=slotinfodata.slottime)
                            data_pop = ordersdelivery.objects.filter(time_slot=slotinfodata.slottime,user_id=serializer.data.get('userid'))
                            invoice_id=[]
                            for data in data_pop:
                                try:
                                    invoice_id.append(data.invoice_id)
                                    print("gotcha")
                                except Exception as e:
                                    print(e)
                                    pass
                            orderwithoutcoordinates=[]
                            created_date = datetime.now().date()
                            created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                            # start = datetime.date.today()
                            # end = start + datetime.timedelta(days=1)
                            if coordinate_type=='with-coordinate':
                                # print("If condition")
                                orderwithoutcoordinates = orderinfo.objects.filter(created_date__date = created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=serializer.data.get('userid'),is_deleted=0,weight__lt=average_vehicle_calculated_weight).exclude(invoice_id__in=invoice_id)
                            elif coordinate_type=='without-coordinate':
                                # print("elif condition")
                                orderwithoutcoordinates = orderinfo.objects.filter(created_date__date=created_date,time_slot=slotinfodata.slottime,is_coordinate=0,userid=serializer.data.get('userid'),is_deleted=0).exclude(invoice_id__in=invoice_id)
                            elif coordinate_type=='orderweight-exceed':
                                #Getting Extra Order weight
                               
                                orderwithoutcoordinates = orderinfo.objects.filter(created_date__date=created_date,time_slot=slotinfodata.slottime,is_coordinate=1,userid=userid,weight__gt=average_vehicle_calculated_weight,is_deleted=0).exclude(invoice_id__in=invoice_id)
                            elif coordinate_type=='manually':
                                orderwithoutcoordinates = ordersdelivery.objects.filter(created_date__date=created_date,is_manually_assigned=1,is_deleted=0,user_id=serializer.data.get('userid', ''),time_slot=slotinfodata.slottime)
                            else:
                                orderwithoutcoordinates = orderinfo.objects.filter(created_date__date=created_date,time_slot=slotinfodata.slottime,userid=userid,is_deleted=0).exclude(invoice_id__in=invoice_id)
                            

                            # print("5555555555   ",orderwithoutcoordinates)
                            orderlist = [{"id": data.id, "shipping_address": data.shipping_address, 
                            "invoice_id": data.invoice_id, 
                            "vehicleid": f'{ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).first().vehicle_id.id if ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).exists() else 0}' , 
                            "serialno": f'{ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).first().serialno if ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).exists() else 0}' , 
                            "is_vehicle_update": ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).first().is_vehicle_update if ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).exists() else False , 
                            "is_priority_change": ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).first().is_priority_change if ordersdelivery.objects.filter(order_id=data.id,invoice_id=data.invoice_id,time_slot=data.time_slot,user_id=userid,is_deleted=0).exists() else False , 
                            "customer_name": data.customer_name, 
                            "invoice_number": data.invoice_number, 
                            "invoice_total": data.invoice_total, 
                            "invoice_balance": data.invoice_balance, 
                            "time_slot": data.time_slot, 
                            "contactno": data.phone_number if coordinate_type=='manually' else data.contactno, 
                            "location_coordinates": data.location_coordinates,
                            "is_deleted": data.is_deleted, 
                            "updated_at": data.updated_at, 
                                            "weight": data.weight, 'userid':data.user_id.id if coordinate_type=='manually' else data.userid.id,'created_date': data.created_date} for data in orderwithoutcoordinates]
                            # print("---------",orderlist)
                           
                    
                    
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': orderlist,
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
                'error': f"{err}",
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
                try:
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
                        'message': 'Vehicle created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                except Exception as e:
                    print(e)
                    data={}
                    data['status']= "Failed"
                    data['status_code']=500
                    data['message']=f'{e}'
                    return Response(data,status.HTTP_500_INTERNAL_SERVER_ERROR)
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

class orders_delivery(APIView):
    
    def patch(self, request):
        try:
            serializer_data  = orders_delivery_serializers(data=request.data)
            status='success'
            status_code=200
            message = "data updated successfully"
            if serializer_data.is_valid():
                print(serializer_data.data)
                vehicle_id = serializer_data.data.get('vehicle_id')
                order_id = serializer_data.data.get('order_id')
                vehicle_obj = vehicleinfo.objects.get(id=vehicle_id)
                order_obj =  orderinfo.objects.get(id = order_id)
                ordersdelivery_id = serializer_data.data.get('id')
                ordersdelivery_obj = ordersdelivery.objects.filter(id = ordersdelivery_id)
                if vehicle_obj and order_obj and ordersdelivery_obj:
                   
                    ordersdelivery_obj.update(
                        order_id=order_obj, 
                        vehicle_id=vehicle_obj,
                        collectedAmount=serializer_data.validated_data.get('collectedAmount', ''),
                        status=serializer_data.validated_data.get('status', ''),
                        upi=serializer_data.validated_data.get('upi', ''),
                        cash=serializer_data.validated_data.get('cash', ''),
                        other=serializer_data.validated_data.get('other', ''),
                        reason=serializer_data.validated_data.get('reason', ''), 
                    )
                else:
                    status_code=404
                    status="Fail"
                    message = "data Not updated"
            else:
                    status_code=300
                    status="Fail"
                    message = "data is Not valid"
            json_data = {
                'status_code': status_code,
                'status': status,
                'messgae': message,
                }
            return Response(json_data, status  = status_code)    
        
        
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAppOrderDetail(APIView):
    # permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetOrderDetailSerializer(data=request.data)
            if serializer.is_valid():
                ordersdelivery_id = serializer.data.get('ordersdeliveryid')
                vehicle_id = serializer.data.get('vehicleid')
                data = ordersdelivery.objects.filter(id=ordersdelivery_id,vehicle_id=vehicle_id)
                print("---------",data)
                if data:
                    orderdata = ordersdelivery.objects.get(id=ordersdelivery_id,vehicle_id=vehicle_id)
                    
                    vehicledata={
                        "ordersdeliveryid":orderdata.id,
                        "order_id": orderdata.order_id.id,
                        "vehicle_id": orderdata.vehicle_id.id,
                        "vehiclename": orderdata.vehicle_id.vehiclename,
                        "time_slot": orderdata.time_slot,
                        'user_id': orderdata.user_id.id,
                        "customer_name": orderdata.customer_name,
                        "phone_number": orderdata.phone_number,
                        'email': orderdata.email,
                        'location_coordinates':orderdata.location_coordinates,
                        'location_url': orderdata.location_url,
                        'weight': orderdata.weight,
                        'shipping_address': orderdata.shipping_address ,
                        'collectedAmount': orderdata.collectedAmount,
                        'invoice_total': orderdata.invoice_total ,
                        'invoice_balance': orderdata.invoice_balance ,
                        'invoice_number': orderdata.invoice_number ,
                        'invoice_id': orderdata.invoice_id ,
                        'status': orderdata.status ,
                        'upi': orderdata.upi ,
                        'cash': orderdata.cash,
                        'other': orderdata.other ,
                        'reason': orderdata.reason,
                        'totalamount':orderdata.upi+orderdata.cash
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
                'error': "{}".format(err),
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAppOrderList_f(APIView):
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = GetOrderListSerializer(data=request.data)
            if serializer.is_valid():
                print("--------------",serializer.data.get('userid', ''))
                vehicledata = vehicleinfo.objects.filter(id=serializer.data.get(
                        'vehicleid', ''))
                if vehicledata:
                    #Getting Order by Vehicleid and is_published is True
                    vehicleobj = ordersdelivery.objects.filter(is_deleted=0,vehicle_id=serializer.data.get(
                        'vehicleid', ''),is_published=1).order_by('serialno')

                    total_collected_amount=0.0
                    total_collected_upi=0.0
                    total_collected_cash=0.0
                    # print("---------",vehicleobj)
                    orderlist=[]
                    for data in vehicleobj:
                        total_collected_amount+=data.upi+data.cash
                        total_collected_upi+=data.upi
                        total_collected_cash+=data.cash
                        coordianteslist=data.location_coordinates.split(" ")
                        # print("-----------",coordianteslist)
                    
                        deliveryorderdata={"ordersdeliveryid":data.id,
                            "order_id": data.order_id.id,
                            "vehicle_id": data.vehicle_id.id,
                            "vehiclename": data.vehicle_id.vehiclename,
                            "time_slot": data.time_slot,
                            'user_id': data.user_id.id,
                            "customer_name": data.customer_name,
                            "phone_number": data.phone_number,
                            'email': data.email,
                            'location_coordinates':data.location_coordinates,
                            'latitude':coordianteslist[0] if len(coordianteslist) ==2 else 0 ,
                            'longitude':coordianteslist[1] if len(coordianteslist) ==2 else 0 ,
                            'location_url': data.location_url,
                            'weight': data.weight,
                            'shipping_address': data.shipping_address ,
                            'collectedAmount': data.collectedAmount,
                            'invoice_total': data.invoice_total ,
                            'invoice_balance': data.invoice_balance ,
                            'invoice_number': data.invoice_number ,
                            'invoice_id': data.invoice_id ,
                            'status': data.status ,
                            'upi': data.upi ,
                            'cash': data.cash,
                            'other': data.other ,
                            'reason': data.reason,
                            'upiamount':data.upi,
                            'totalamount':data.upi+data.cash
                            } 
                        orderlist.append(deliveryorderdata)
                        # print("-------+++++++++++--------    ",orderlist)
                    if orderlist :
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': orderlist,
                            'total_collected_amount': total_collected_amount,
                            'total_collected_upi': total_collected_upi,
                            'total_collected_cash': total_collected_cash,
                            'message': 'Order found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        print("================")
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'Order not found'
                        }
                        return Response(json_data, status.HTTP_204_NO_CONTENT)
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
                'error': f"{err}",
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class NewFetchInvoiceData(APIView):
    # permission_classes = [IsAuthenticated]
    # Add warehouse cordinates Post Reuqest
    def post(self, request):
        try:
            print("------------New fetch invoice------")
            req = requests.Session()
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = User.objects.filter(id=serializer.data.get(
                        'userid', ''))
                if usercordiantes:
                    # data=zohoaccount.objects.get(userid=serializer.data.get(
                    #     'userid', ''))
                    # print("tttttoken ",data.refreshtoken)
                    parameters = {
                    # "refresh_token":data.refreshtoken,
                    # "refresh_token":"1000.25a090d5c14fadc4b1084d05556d077e.289204add6d03719a38814aa6c917ac6",#Vishal
                    "refresh_token":"1000.1ffe9bac5af892bbef2638945a872502.88932d5e0bdbcb08ebaac8e827fe32e7",#Sangam
                    # "client_id":data.clientid,
                    # "client_id":'1000.6CUWGWRSYBPGDHV0DG1L27R4M51WHX',#Vishal
                    "client_id":'1000.KNTTWIQG6BRID6XQGEURG025O51XXD',#Sangam
                    # "client_secret":data.clientsecret,
                    # "client_secret":'6d8f85d3802ba38fd768a37c608a0ac30acbf6e730',#Vishal
                    "client_secret":'c7a0541ea8b37ea7716dc368d393fdab5f11891ae1',#Sangam
                    # "redirect_uri":data.clientsecret,
                    # "redirect_uri":'https://www.google.co.in',
                    "redirect_uri":'https://onlinethela.online/add-access',
                    "grant_type":"refresh_token",
                    }
                    
 
                    response = req.post("https://accounts.zoho.in/oauth/v2/token?", params=parameters)
                    if response.status_code == 200:
                        data =   response.json()
                        # print("+++++++++  ",data)
                        accesstoken = data['access_token']
                        # print("-------",accesstoken)
                        currentdate=datetime.now().date()
                        headers = {
                        'Content-Type':'application/json',
                        'Authorization':'Zoho-oauthtoken ' + str(accesstoken)
                                }

                        response = req.get("https://books.zoho.in/api/v3/invoices?date_start={}&date_end={}".format(currentdate,currentdate), headers=headers)
                        if response.status_code == 200:
                            data1 = response.json()
                            invoices=data1.get("invoices")
                            if invoices:
                                orderupdatemessage="All invoices already exist"
                                countdata=0
                                for invoice in invoices:
                                    # Getting Invoice data
                                    zoho_last_modified_time = invoice.get('last_modified_time')
                                    zoho_branch_id = invoice.get('branch_id')
                                    user_obj = User.objects.get(id=serializer.data.get(
                                        'userid', ''))
                                    branch_obj_id = user_obj.branch_id_id
                                    branch_obj = Branches.objects.get(id=branch_obj_id)
                                    branch_id = branch_obj.zoho_branch_id
                                    if branch_id!=zoho_branch_id:
                                        continue
                                    list =datetime.strptime(zoho_last_modified_time, "%Y-%m-%dT%H:%M:%S+%f")    
                                    zoho_last_modified_time = list.strftime("%H:%M:%S")
                                    orderobj_updated=orderinfo.objects.filter(invoice_id=invoice.get('invoice_id',''),userid=serializer.data.get('userid', ''))
                                    if orderobj_updated:
                                        obj = orderinfo.objects.get(invoice_id=invoice.get('invoice_id',''),userid=serializer.data.get('userid', ''))
                                        previous_updated_time = obj.zoho_updated_time
                                        if previous_updated_time !='':
                                            # previous_updated_time = previous_updated_time.time()
                                            # previous_updated_time = previous_updated_time.strftime("%H:%M:%S")
                                            if previous_updated_time>=zoho_last_modified_time:
                                                continue
                                    itemslist_of_invoice = req.get("https://books.zoho.in/api/v3/invoices/{}".format(invoice.get('invoice_id')), headers=headers)
                                    if itemslist_of_invoice.status_code == 200:
                                        cf_location_coordinates=itemslist_of_invoice.json().get("invoice").get("cf_location_coordinates",0)
                                        cf_location_url=itemslist_of_invoice.json().get("invoice").get("cf_location_url",0)
                                        invoicecreateddatetime=invoice.get('date','')
                                        cusomercontact=itemslist_of_invoice.json().get("invoice").get("contact_persons_details",'')[0].get("mobile") if itemslist_of_invoice.json().get("invoice").get("contact_persons_details",'')[0].get("mobile") else itemslist_of_invoice.json().get("invoice").get("contact_persons_details",'')[0].get('phone')

                                    
                                        totalitemwaight=0
                                        for item in itemslist_of_invoice.json().get("invoice").get("line_items"):
                                            # print("=======   ",item)
                                                
                                            getweight = iteminfo.objects.filter(zoho_item_id=item.get("item_id"),userid=serializer.data.get('userid', ''))
                                            #Calculating items waight ----------
                                            if getweight:
                                                getweightdata = iteminfo.objects.get(zoho_item_id=item.get("item_id"),userid=serializer.data.get('userid', ''))
                                                #Multiply item quantity with item waight
                                                totalitemwaight+=item.get("quantity")*getweightdata.item_waight
                                        
                                        userobj = User.objects.get(id=serializer.data.get('userid', ''))
                                        #Check Invoice id exits for particular user or not
                                        orderobj=orderinfo.objects.filter(invoice_id=invoice.get('invoice_id',''),userid=serializer.data.get('userid', ''))
                                        # print("---------------",invoice.get("cf_location_coordinate"))
                                        bool_value=0
                                        if checkcoordinate(s=itemslist_of_invoice.json().get("invoice").get("cf_location_coordinates")):
                                            bool_value=1
                                        from pytz import timezone 
                                        time_now =  datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S.%f')
                                        str_time_now = str(time_now)
                                        if not orderobj:
                                            #Check Is Quardinates available
                                            orderdata=orderinfo.objects.create(
                                                userid=userobj,
                                                shipping_address=invoice.get("shipping_address").get("address",''),
                                                invoice_id=invoice.get("invoice_id",''),
                                                customer_id=invoice.get("customer_id",''),
                                                weight=totalitemwaight,
                                                customer_name=invoice.get("customer_name",''),
                                                invoice_number=invoice.get("invoice_number",''),
                                                invoice_total=invoice.get("total",''),
                                                invoice_balance=invoice.get("balance",''),
                                                time_slot=invoice.get("cf_delivery_slots",''),
                                                contactno=cusomercontact,
                                                location_coordinates=cf_location_coordinates,
                                                location_url=cf_location_url,
                                                is_coordinate=bool_value,
                                                is_deleted=0,
                                                updated_at = time_now,
                                                created_date=invoicecreateddatetime,
                                                zoho_updated_time = zoho_last_modified_time
                                            )
                                            orderdata.save()
                                            orderupdatemessage="Invoices updated"
                                        else:
                                            print("Else Condition ----------->>>>  ::::: ",countdata)
                                            orderobj.update(                                                
                                                    shipping_address=invoice.get("shipping_address").get("address",''),
                                                    customer_id=invoice.get("customer_id",''),
                                                    weight=totalitemwaight,
                                                    customer_name=invoice.get("customer_name",''),
                                                    invoice_number=invoice.get("invoice_number",''),
                                                    invoice_total=invoice.get("total",''),
                                                    invoice_balance=invoice.get("balance",''),
                                                    time_slot=invoice.get("cf_delivery_slots",''),
                                                    contactno=cusomercontact,
                                                    location_coordinates=cf_location_coordinates,
                                                    location_url=cf_location_url,
                                                    is_coordinate=bool_value,
                                                    updated_at=time_now,
                                                    created_date=invoicecreateddatetime,
                                                    zoho_updated_time = zoho_last_modified_time)
                                        # print("@@@@@@@@@@@@@ 22222222")
                                        countdata+=1
                                        
                                          
                                else:
                                    json_data = {
                                    'status_code': 200,
                                    'status': 'Success',
                                    'data': '',
                                    'message': orderupdatemessage
                                    }
                                    return Response(json_data, status.HTTP_200_OK)
                            else:
                                json_data = {
                                'status_code': 400,
                                'status': 'Failed',
                                'data': 'Invoices not found',
                                'message': "Data not found"
                                }
                                return Response(json_data, status.HTTP_400_BAD_REQUEST)

                        else:
                            json_data = {
                            'status_code': 400,
                            'status': 'Failed',
                            'data': '',
                            'message': "{}".format(response.json())
                            }
                            return Response(json_data, status.HTTP_400_BAD_REQUEST)
                else:
                    json_data = {
                        'status_code': 400,
                        'status': 'Failed',
                        'message': 'User not found'
                    }
                    return Response(json_data, status.HTTP_400_BAD_REQUEST)
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class GetLastInvoiceUpdatedDate_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            # print("--------------")
            mycheckdata=orderinfo.objects.filter(userid=request.data.get("userid") if request.data.get("userid") else 0).last()
            #Check Data 
            if mycheckdata:
                # print("--------------->>>>>>>   ",mycheckdata.updated_at.strftime("%H:%M:%S"))
                # print("--------------->>>>>>>   ",type(mycheckdata.updated_at))
                newdata = {
                        "userid": mycheckdata.userid.id,
                        "customer_id": mycheckdata.customer_id,
                        "weight": mycheckdata.weight,
                        "customer_name": mycheckdata.customer_name,
                        "invoice_number": mycheckdata.invoice_number,
                        "invoice_total": mycheckdata.invoice_total,
                        "invoice_balance": mycheckdata.invoice_balance,
                        "time_slot": mycheckdata.time_slot,
                        "contactno": mycheckdata.contactno,
                        "location_coordinates": mycheckdata.location_coordinates,
                        "is_coordinate": mycheckdata.is_coordinate,
                        "is_deleted": mycheckdata.is_deleted,
                        "updated_at": mycheckdata.updated_at.strftime("%H:%M:%S"),
                        "created_date": mycheckdata.created_date,
                    }
                # print("----------->>>>>>>     ",newdata)
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class AssignOrdertoVehicle_fun(APIView):
    # Handling Post Reuqest
    def post(self, request):
        try:
            # print("iiiiiiiii ",request.id)
            serializer = NewAssignOrdertoVehicleSerializer(data=request.data)
            if serializer.is_valid():
                assignorderlist=serializer.data.get('assignorderlist')
                type=serializer.data.get('type')
                assignorderlistconvertedlist=json.loads(assignorderlist)
                message="Order not assigned to vehicle."
                serialcount=1
                previousvehicle=''
                nextvehicle=''
                is_set_manual=0
                if type=='manual':
                    is_set_manual=1
                for vehicle_order_obj in assignorderlistconvertedlist:
                    vehicleid= vehicle_order_obj.get("vehicleid")
                    orderid=vehicle_order_obj.get("orderid")
                    userid=vehicle_order_obj.get("userid")
                    invoiceid=vehicle_order_obj.get("invoiceid")
                    slotid=vehicle_order_obj.get("slotid")
                    nextvehicle=vehicle_order_obj.get("vehicleid")
                    if previousvehicle!=nextvehicle:
                        previousvehicle=nextvehicle
                        serialcount=1

                    
                    userinfo = User.objects.filter(id=userid).exists()
                    # userinfo = User.objects.filter(id=userid)
                    if userinfo:
                        userinfo = User.objects.get(id=userid)
                        print("-------UserInfo -------- ",userinfo)
                        checkvehicle = vehicleinfo.objects.get(id=vehicleid , userid=userid)
                        # print("--------------",userinfo.get("username"))
                        if checkvehicle:
                            print("-------checkvehicle -------- ",checkvehicle)
                            checkslotinfo = slotinfo.objects.get(id=slotid , userid=userid)
                            if checkslotinfo:
                                print("-------checkslotinfo -------- ",checkslotinfo)
                                checkorderinfo = orderinfo.objects.get(id=orderid ,invoice_id=invoiceid, userid=userid)
                                if checkorderinfo:
                                    print("2222222222222       00000",checkorderinfo)
                                    checkorderdelivery=ordersdelivery.objects.filter(invoice_id=invoiceid,user_id=userid,is_deleted=0)
                                    print("--------",checkorderdelivery)
                                    if not checkorderdelivery:

                                        orderdata=ordersdelivery.objects.create(
                                            order_id=checkorderinfo,
                                            vehicle_id=checkvehicle,
                                            time_slot=checkslotinfo.slottime,
                                            user_id=userinfo,
                                            customer_name=checkorderinfo.customer_name,
                                            phone_number=checkorderinfo.contactno,
                                            email='',
                                            location_coordinates=checkorderinfo.location_coordinates,
                                            location_url='',
                                            weight=checkorderinfo.weight,
                                            shipping_address=checkorderinfo.shipping_address,
                                            collectedAmount=0,
                                            invoice_total=checkorderinfo.invoice_total,
                                            invoice_balance=checkorderinfo.invoice_balance,
                                            invoice_number=checkorderinfo.invoice_number,
                                            invoice_id=checkorderinfo.invoice_id,
                                            status='Pending',
                                            serialno=serialcount,
                                            upi=0,
                                            cash=0,
                                            other=0,
                                            reason='',
                                            is_deleted=0,
                                            is_published=0,
                                            updated_at=datetime.now(),
                                            created_date=checkorderinfo.created_date,
                                            is_vehicle_update=1,
                                            is_priority_change=0,
                                            is_manually_assigned=is_set_manual
                                        )
                                        orderdata.save()
                                        checkvehicle.is_vehicle_not_available=1
                                        checkvehicle.save()
                                        message="Order assigned to vehicle."
                                        serialcount+=1

                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'message': message
                }
                return Response(json_data, status.HTTP_200_OK)
            else:
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
    # Handling Patch Reuqest
    def patch(self, request):
        try:
            # print("iiiiiiiii ",request.id)
            serializer = NewAssignOrdertoVehicleSerializer(data=request.data)
            if serializer.is_valid():
                assignorderlist=serializer.data.get('assignorderlist')
                assignorderlistconvertedlist=json.loads(assignorderlist)
                message="Order not change"
                for vehicle_order_obj in assignorderlistconvertedlist:
                    vehicleid= vehicle_order_obj.get("vehicleid")
                    orderid=vehicle_order_obj.get("orderid")
                    userid=vehicle_order_obj.get("userid")
                    invoiceid=vehicle_order_obj.get("invoiceid")
                    slotid=vehicle_order_obj.get("slotid")
                    
                    userinfo = User.objects.filter(id=userid).exists()
                    # userinfo = User.objects.filter(id=userid)
                    if userinfo:
                        userinfo = User.objects.get(id=userid)
                        print("-------UserInfo -------- ",userinfo)
                        checkvehicle = vehicleinfo.objects.get(id=vehicleid , userid=userid)
                        # print("--------------",userinfo.get("username"))
                        if checkvehicle:
                            print("-------checkvehicle -------- ",checkvehicle)
                            checkslotinfo = slotinfo.objects.get(id=slotid , userid=userid)
                            if checkslotinfo:
                                print("-------checkslotinfo -------- ",checkslotinfo)
                                checkorderinfo = orderinfo.objects.get(id=orderid ,invoice_id=invoiceid, userid=userid)
                                if checkorderinfo:
                                    print("2222222222222       00000",checkorderinfo)
                                    checkorderdelivery=ordersdelivery.objects.get(invoice_id=invoiceid,user_id=userid,is_deleted=0)
                                    print("--------",checkorderdelivery)
                                    if  checkorderdelivery:
                                        checkorderdelivery.vehicle_id=checkvehicle
                                        checkorderdelivery.is_vehicle_update=0 if checkorderdelivery.vehicle_id==checkvehicle.id else 1
                                        checkorderdelivery.updated_at=timezone.now()
                                        checkorderdelivery.save()
                                        checkvehicle.is_vehicle_not_available=1
                                        checkvehicle.save()
                                        message="Order  changed"
                                        
                     
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'message': message
                }
                return Response(json_data, status.HTTP_200_OK)
            else:
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class AllocatedToVehicleDeliveryOrderList_f(APIView):
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                # print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', '')).exists()
                created_date = datetime.now().date()
                created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                if vehicledata:
                    vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                        'userid', ''))
                    finaldelveyorder=[]
                    if vehicleobj:
                        for vehcledata in vehicleobj:
                            dictdata={}
                            # print("------------>>>> ",vehcledata.id)
                            vehicleobj = ordersdelivery.objects.filter(created_date__date=created_date,is_deleted=0,user_id=serializer.data.get(
                                'userid', ''),is_published=1,vehicle_id=vehcledata.id).order_by('serialno')
                            
                            total_collected_amount=0.0
                            total_collected_upi=0.0
                            total_collected_cash=0.0
                            # print("---------",vehicleobj)
                            orderlist=[]
                            for data in vehicleobj:
                                total_collected_amount+=data.upi+data.cash
                                total_collected_upi+=data.upi
                                total_collected_cash+=data.cash
                            
                                deliveryorderdata={"ordersdeliveryid":data.id,
                                    "order_id": data.order_id.id,
                                    "vehicle_id": data.vehicle_id.id,
                                    "vehiclename": data.vehicle_id.vehiclename,
                                    "time_slot": data.time_slot,
                                    'user_id': data.user_id.id,
                                    "customer_name": data.customer_name,
                                    "phone_number": data.phone_number,
                                    'email': data.email,
                                    'location_coordinates':data.location_coordinates,
                                    'location_url': data.location_url,
                                    'weight': data.weight,
                                    'shipping_address': data.shipping_address ,
                                    'collectedAmount': data.collectedAmount,
                                    'invoice_total': data.invoice_total ,
                                    'invoice_balance': data.invoice_balance ,
                                    'invoice_number': data.invoice_number ,
                                    'invoice_id': data.invoice_id ,
                                    'status': data.status ,
                                    'upi': data.upi ,
                                    'cash': data.cash,
                                    'other': data.other ,
                                    'serialno': data.serialno ,
                                    'reason': data.reason,
                                    'upiamount':data.upi,
                                    'totalamount':data.upi+data.cash+data.other
                                    } 
                                orderlist.append(deliveryorderdata)
                            dictdata.update({"vehicleid":vehcledata.id,"vehiclename":vehcledata.vehiclename,"orderdatabyvehicle":orderlist,'total_collected_amount': total_collected_amount,
                            'total_collected_upi': total_collected_upi,
                            'total_collected_cash': total_collected_cash})
                            finaldelveyorder.append(dictdata)
                            # finaldelveyorder+=vehicleorderlist
                    if finaldelveyorder :
                        # total_collected_amount =vehicleorderlist[0].get('totalamount')
                        
                        json_data = {
                            'status_code': 200,
                            'status': 'Success',
                            'data': finaldelveyorder,
                            'message': 'Order found'
                        }
                        return Response(json_data, status.HTTP_200_OK)
                    else:
                        print("================")
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'Order not found'
                        }
                        return Response(json_data, status.HTTP_204_NO_CONTENT)
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
                'error': f"{err}",
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class PublishOrderDeliveryList_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            print("--------------")
            datacheck=User.objects.filter(id=request.data.get("userid") if request.data.get("userid") else 0)
            #Check Data 
            if datacheck:
                created_date = datetime.now().date()
                created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                checkorderdata=ordersdelivery.objects.filter(created_date__date = created_date,user_id=request.data.get("userid") ,is_deleted=0)
                if checkorderdata:
                    #Getting data of user
                    checkupdate=checkorderdata.update(
                        is_published=1
                    )
            
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': checkupdate,
                        'message': 'Order published successfully'
                    }
                    return Response(json_data, status.HTTP_200_OK)
                else:
                    json_data = {
                        'status_code': 204,
                        'status': 'Success',
                        'data': '',
                        'message': 'Order not found for this user'
                    }
                    return Response(json_data, status.HTTP_204_NO_CONTENT)
            else:
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)



class GetZohoCredentialByUserID_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            print("--------------")
            datacheck=User.objects.filter(id=request.data.get("userid") if request.data.get("userid") else 0)
            # print("------",datacheck)
            #Check Data 
            if datacheck:
                #Getting data of user
                data = zohoaccount.objects.filter(userid=request.data.get("userid"),is_deleted=0)
                if data:
                    # print("==========",data)
                    newdata = {
                            "id": data.userid.id,
                            "clientid": data.clientid,
                            "clientsecret": data.clientsecret,
                            "accesstoken": data.accesstoken,
                            "refreshtoken": data.refreshtoken,
                            "redirecturi": data.redirecturi,
                            "is_deleted": data.is_deleted,
                            "created_at": data.created_at
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)





class TestCaseCheckAPI_fun(APIView):
    def post(self, request):
        try:
            print("--------------",datetime.now())
            json_data = {
                'status_code': 200,
                'status': 'Success',
                'data': '',
                'message': 'Data found'
            }
            return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)





class AssignSerialNumberToOrders_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
            try:
                # print("iiiiiiiii ",request.id)
                serializer = AssignSerialNumberToOrdersSerializer(data=request.data)
                if serializer.is_valid():
                    # ordersdeliveryid=serializer.data.get('ordersdeliveryid')
                    userid=serializer.data.get('userid')
                    listofinvoiceid_serialno=serializer.data.get('listofinvoiceid_serialno')
                    slotid=serializer.data.get('slotid')
                    userinfo = User.objects.filter(id=userid)
                    # userinfo = User.objects.filter(id=userid)
                    if userinfo:
                        userinfo = User.objects.get(id=userid)

                        checkslotinfo = slotinfo.objects.filter(id=slotid , userid=userid).first()
                        if checkslotinfo:
                            newserialnumberwithinvoiceid = json.loads(listofinvoiceid_serialno)
                            message="Order not update successfully"
                            from operator import itemgetter
                            import operator
                            from operator import itemgetter
                            for data in newserialnumberwithinvoiceid:
                                data["serialno"]=int(data.get("serialno"))
                            x = newserialnumberwithinvoiceid
                            test = sorted(x, key=itemgetter('serialno'))
                            newserialnumberwithinvoiceid = test
                            for invdata in newserialnumberwithinvoiceid:
                                # # print(invdata.get("serialno"),"-----invoice id----",invdata.get("invoice_id"))
                                # checkorderdelivery=ordersdelivery.objects.filter(invoice_id=invdata.get("invoice_id"),time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0)
                                # print("--------",checkorderdelivery)
                                # if checkorderdelivery:
                                #     serialno=invdata.get("serialno")
                                #     is_priority_change=1
                                #     vehicleid=invdata.get("vehicleid")
                                #     total_serialno = ordersdelivery.objects.filter(vehicle_id=vehicleid,time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0,is_vehicle_update=1)
                                #     print("Updated Vehicle data : ",total_serialno)
                                #     for ndata in total_serialno:
                                #         count=0
                                #         olddataobj =ordersdelivery.objects.filter(vehicle_id=vehicleid,time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0,is_vehicle_update=0)
                                #         for olddata in olddataobj:
                                #             print("llddddddddddddddddd      : ",len(olddataobj))
                                #             if ndata.serialno==olddata.serialno:
                                #                 while len(olddataobj)>count:
                                #                     # print("sllwhile loop--------------")
                                #                     olddata.serialno=olddata.serialno+1
                                #                     count+=1
                                checkorderdelivery=ordersdelivery.objects.filter(invoice_id=invdata.get("invoice_id"),time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0)
                                print("--------",checkorderdelivery)
                                if checkorderdelivery:
                                    serialno=invdata.get("serialno")
                                    is_priority_change=1
                                    vehicle_id=invdata.get("vehicleid")
                                    maxi = ordersdelivery.objects.filter(vehicle_id=vehicle_id,time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0).count()
                                    mini = int(serialno)
                                    data_obj = ordersdelivery.objects.filter(vehicle_id=vehicle_id,serialno__range=[mini, maxi],time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0)
                                    for obj in data_obj:
                                        is_priority_change=1
                                        obj.is_priority_change=is_priority_change
                                        obj.serialno=obj.serialno+1
                                        obj.save()
                                    orderdata=checkorderdelivery.update(
                                        serialno=serialno,
                                        updated_at=timezone.now(),
                                        is_priority_change=is_priority_change
                                    )
                                    message="Order update successfully"
                                                   

                                    # number = int(serialno)
                                    # if total_serialno>=number:
                                    #     while number<=total_serialno:
                           
                                    #         obj = ordersdelivery.objects.get(vehicle_id=vehicleid,invoice_id=invdata.get("invoice_id"), serialno=total_serialno,time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0)
                                    #         obj.is_priority_change=is_priority_change
                                    #         obj.serialno=obj.serialno+1
                                    #         obj.save()
                                    #         total_serialno=total_serialno-1
                                            
                                    orderdata=checkorderdelivery.update(
                                        serialno=serialno,
                                        updated_at=timezone.now(),
                                        is_priority_change=is_priority_change
                                    )
                            
                                # checkorderdelivery=ordersdelivery.objects.filter(invoice_id=invdata.get("invoice_id"),time_slot=checkslotinfo.slottime,user_id=userid,is_deleted=0)
                                # print("--------",checkorderdelivery)
                                # if checkorderdelivery:
                                #     orderdata=checkorderdelivery.update(
                                #         serialno=invdata.get("serialno"),
                                #         updated_at=timezone.now(),
                                #     )
                                    message="Order update successfully"
                            if message=="Order update successfully":
                                json_data = {
                                    'status_code': 200,
                                    'status': 'Success',
                                    'message': message
                                }
                                return Response(json_data, status.HTTP_200_OK)
                            else:
                                json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': "Order not update successfully"
                                }
                                return Response(json_data, status.HTTP_204_NO_CONTENT)
                           
                        else:
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Slot not found for this userid'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
                       
                    else:
                        json_data = {
                            'status_code': 204,
                            'status': 'Success',
                            'message': 'User not found'
                        }
                        return Response(json_data, status.HTTP_204_NO_CONTENT)
                else:
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
                    'error': f'{err}',
                    'remark': 'Landed in exception',
                }
                return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)




class HistoryAllocatedToVehicleDeliveryOrderList_f(APIView):
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = HistoryGetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                # print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', '')).exists()
                if vehicledata:
                    checkslot = slotinfo.objects.filter(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                    if checkslot:
                        slotdata = slotinfo.objects.get(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                        # print("-------->>> ",slotdata.slottime)
                        vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                            'userid', ''))
                        finaldelveyorder=[]
                        if vehicleobj:
                            for vehcledata in vehicleobj:
                                dictdata={}
                                # print("------------>>>> ",vehcledata.id)
                                vehicleobj = ordersdelivery.objects.filter(is_deleted=1,user_id=serializer.data.get(
                                    'userid', ''),vehicle_id=vehcledata.id,time_slot=slotdata.slottime,is_published=1).order_by('serialno')
                                
                                total_collected_amount=0.0
                                total_collected_upi=0.0
                                total_collected_cash=0.0
                                # print("---------",vehicleobj)
                                orderlist=[]
                                for data in vehicleobj:
                                    total_collected_amount+=data.upi+data.cash
                                    total_collected_upi+=data.upi
                                    total_collected_cash+=data.cash
                                
                                    deliveryorderdata={"ordersdeliveryid":data.id,
                                        "order_id": data.order_id.id,
                                        "vehicle_id": data.vehicle_id.id,
                                        "vehiclename": data.vehicle_id.vehiclename,
                                        "time_slot": data.time_slot,
                                        'user_id': data.user_id.id,
                                        "customer_name": data.customer_name,
                                        "phone_number": data.phone_number,
                                        'email': data.email,
                                        'location_coordinates':data.location_coordinates,
                                        'location_url': data.location_url,
                                        'weight': data.weight,
                                        'shipping_address': data.shipping_address ,
                                        'collectedAmount': data.collectedAmount,
                                        'invoice_total': data.invoice_total ,
                                        'invoice_balance': data.invoice_balance ,
                                        'invoice_number': data.invoice_number ,
                                        'invoice_id': data.invoice_id ,
                                        'status': data.status ,
                                        'upi': data.upi ,
                                        'cash': data.cash,
                                        'other': data.other ,
                                        'serialno': data.serialno ,
                                        'reason': data.reason,
                                        'upiamount':data.upi,
                                        'totalamount':data.upi+data.cash+data.other
                                        } 
                                    orderlist.append(deliveryorderdata)
                                dictdata.update({"vehicleid":vehcledata.id,"vehiclename":vehcledata.vehiclename,"orderdatabyvehicle":orderlist,'total_collected_amount': total_collected_amount,
                                'total_collected_upi': total_collected_upi,
                                'total_collected_cash': total_collected_cash})
                                finaldelveyorder.append(dictdata)
                                # finaldelveyorder+=vehicleorderlist
                        if finaldelveyorder :
                            # total_collected_amount =vehicleorderlist[0].get('totalamount')
                            
                            json_data = {
                                'status_code': 200,
                                'status': 'Success',
                                'data': finaldelveyorder,
                                'message': 'Order found'
                            }
                            return Response(json_data, status.HTTP_200_OK)
                        else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Order not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
                    else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Slot not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
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
                'error': f"{err}",
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class RootOptimizeOrderDeliveryList_f(APIView):
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = HistoryGetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                # print("--------------",serializer.data.get('userid', ''))
                vehicledata = User.objects.filter(id=serializer.data.get(
                        'userid', '')).exists()
                type = serializer.data.get('type', '')

                if vehicledata:
                    checkslot = slotinfo.objects.filter(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                    if checkslot:
                        slotdata = slotinfo.objects.get(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                        # print("-------->>> ",slotdata.slottime)
                        vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                            'userid', ''))
                        finaldelveyorder=[]
                        data = ordersdelivery.objects.filter(is_manually_assigned=1,is_deleted=0,user_id=serializer.data.get('userid', ''))
                        list_of_data=[]
                        for d in data:
                            print(d)
                            d_value=d.vehicle_id_id
                            if d_value not in list_of_data:
                                list_of_data.append(d_value)
                        if type == "ro":
                            vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get('userid', '')).exclude(id__in=list_of_data)
                        if vehicleobj:
                            for vehcledata in vehicleobj:
                                dictdata={}
                                # print("------------>>>> ",vehcledata.id)
                                if type=='ro':
                                    vehicleobj = ordersdelivery.objects.filter(is_deleted=0,user_id=serializer.data.get(
                                    'userid', ''),vehicle_id=vehcledata.id,time_slot=slotdata.slottime,is_published=0).exclude(vehicle_id__in=list_of_data).order_by('serialno')
                                
                                elif type=='manual':
                                    vehicleobj = ordersdelivery.objects.filter(is_deleted=0,user_id=serializer.data.get(
                                    'userid', ''),vehicle_id=vehcledata.id,time_slot=slotdata.slottime,is_published=0).order_by('serialno')
                                
                                total_collected_amount=0.0
                                total_collected_upi=0.0
                                total_collected_cash=0.0
                                # print("---------",vehicleobj)
                                orderlist=[]
                                for data in vehicleobj:
                                    total_collected_amount+=data.upi+data.cash
                                    total_collected_upi+=data.upi
                                    total_collected_cash+=data.cash
                                
                                    deliveryorderdata={"ordersdeliveryid":data.id,
                                        "order_id": data.order_id.id,
                                        "vehicle_id": data.vehicle_id.id,
                                        "is_vehicle_not_available": data.vehicle_id.is_vehicle_not_available,
                                        "vehiclename": data.vehicle_id.vehiclename,
                                        "time_slot": data.time_slot,
                                        'user_id': data.user_id.id,
                                        "customer_name": data.customer_name,
                                        "phone_number": data.phone_number,
                                        'email': data.email,
                                        'location_coordinates':data.location_coordinates,
                                        'location_url': data.location_url,
                                        'weight': data.weight,
                                        'shipping_address': data.shipping_address ,
                                        'collectedAmount': data.collectedAmount,
                                        'invoice_total': data.invoice_total ,
                                        'invoice_balance': data.invoice_balance ,
                                        'invoice_number': data.invoice_number ,
                                        'invoice_id': data.invoice_id ,
                                        'status': data.status ,
                                        'upi': data.upi ,
                                        'cash': data.cash,
                                        'other': data.other ,
                                        'other': data.other ,
                                        'is_vehicle_update': data.is_vehicle_update ,
                                        'is_priority_change': data.is_priority_change ,
                                        'serialno': data.serialno ,
                                        'is_published': data.is_published ,
                                        'is_manually_assigned': data.is_manually_assigned ,
                                        'reason': data.reason,
                                        'upiamount':data.upi,
                                        'totalamount':data.upi+data.cash+data.other
                                        } 
                                    orderlist.append(deliveryorderdata)
                                dictdata.update({"vehicleid":vehcledata.id,"vehiclename":vehcledata.vehiclename,"data":orderlist})
                                finaldelveyorder.append(dictdata)
                                # finaldelveyorder+=vehicleorderlist
                        if finaldelveyorder :
                            # total_collected_amount =vehicleorderlist[0].get('totalamount')
                            
                            json_data = {
                                'status_code': 200,
                                'status': 'Success',
                                'data': finaldelveyorder,
                                'message': 'Order found'
                            }
                            return Response(json_data, status.HTTP_200_OK)
                        else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Order not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
                    else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Slot not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
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
                'error': f"{err}",
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class manally_assign_list(APIView):
    permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = HistoryGetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                vehicledata = User.objects.filter(id=serializer.data.get('userid', '')).exists()
                if vehicledata:
                    checkslot = slotinfo.objects.filter(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                    if checkslot:
                        slotdata = slotinfo.objects.get(id=serializer.data.get('slotinfoid', ''),userid=serializer.data.get('userid', ''),is_deleted=0)
                        # print("-------->>> ",slotdata.slottime)
                        vehicleobj = vehicleinfo.objects.filter(is_deleted=0,userid=serializer.data.get(
                            'userid', ''))
                        finaldelveyorder=[]
                        if vehicleobj:
                            for vehcledata in vehicleobj:
                                dictdata={}
                                coordinate_type=serializer.data.get('coordinate_type')
                                created_date = datetime.now().date()
                                created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
                                # print("------------>>>> ",vehcledata.id)
                                if coordinate_type=='manually':
                                    vehicleobj = ordersdelivery.objects.filter(created_date__date = created_date,is_manually_assigned=1,is_deleted=1,user_id=serializer.data.get('userid', ''),vehicle_id=vehcledata.id,time_slot=slotdata.slottime).order_by('serialno')
                                else:
                                    vehicleobj = ordersdelivery.objects.filter(created_date__date = created_date,is_manually_assigned=0,is_deleted=1,user_id=serializer.data.get(
                                    'userid', ''),vehicle_id=vehcledata.id,time_slot=slotdata.slottime).order_by('serialno')
                                total_collected_amount=0.0
                                total_collected_upi=0.0
                                total_collected_cash=0.0
                                # print("---------",vehicleobj)
                                orderlist=[]
                                for data in vehicleobj:
                                    total_collected_amount+=data.upi+data.cash
                                    total_collected_upi+=data.upi
                                    total_collected_cash+=data.cash
                                
                                    deliveryorderdata={"ordersdeliveryid":data.id,
                                        "order_id": data.order_id.id,
                                        "vehicle_id": data.vehicle_id.id,
                                        "vehiclename": data.vehicle_id.vehiclename,
                                        "time_slot": data.time_slot,
                                        'user_id': data.user_id.id,
                                        "customer_name": data.customer_name,
                                        "phone_number": data.phone_number,
                                        'email': data.email,
                                        'location_coordinates':data.location_coordinates,
                                        'location_url': data.location_url,
                                        'weight': data.weight,
                                        'shipping_address': data.shipping_address ,
                                        'collectedAmount': data.collectedAmount,
                                        'invoice_total': data.invoice_total ,
                                        'invoice_balance': data.invoice_balance ,
                                        'invoice_number': data.invoice_number ,
                                        'invoice_id': data.invoice_id ,
                                        'status': data.status ,
                                        'upi': data.upi ,
                                        'cash': data.cash,
                                        'other': data.other ,
                                        'serialno': data.serialno ,
                                        'reason': data.reason,
                                        'upiamount':data.upi,
                                        'totalamount':data.upi+data.cash+data.other
                                        } 
                                    orderlist.append(deliveryorderdata)
                                dictdata.update({"vehicleid":vehcledata.id,"vehiclename":vehcledata.vehiclename,"orderdatabyvehicle":orderlist,'total_collected_amount': total_collected_amount,
                                'total_collected_upi': total_collected_upi,
                                'total_collected_cash': total_collected_cash})
                                finaldelveyorder.append(dictdata)
                                # finaldelveyorder+=vehicleorderlist
                        if finaldelveyorder :
                            # total_collected_amount =vehicleorderlist[0].get('totalamount')
                            
                            json_data = {
                                'status_code': 200,
                                'status': 'Success',
                                'data': finaldelveyorder,
                                'message': 'Order found'
                            }
                            return Response(json_data, status.HTTP_200_OK)
                        else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Order not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
                    else:
                            print("================")
                            json_data = {
                                'status_code': 204,
                                'status': 'Success',
                                'message': 'Slot not found'
                            }
                            return Response(json_data, status.HTTP_204_NO_CONTENT)
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
                'error': f"{err}",
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class AllVehicleList_fun(APIView):
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
                    # print("=============",vehicleobj)
                    vehiclelist=[]
                    for data in vehicleobj:
                        totalvehicle_remaining_weight=0
                        for delivery_order in ordersdelivery.objects.filter(vehicle_id=data.id,user_id=data.userid.id,is_deleted=0):
                            totalvehicle_remaining_weight+=delivery_order.weight
                        datadict={
                            "id": data.id,
                            "vehiclename": data.vehiclename,
                            "phone": data.phone,
                            "maxorders": data.maxorders,
                            "weightcapacity": data.weightcapacity,
                            'userid': data.userid.id,
                            'created_at': data.created_at,
                            'password': data.password,
                            'vehicle_remaining_weight': int(data.weightcapacity)-totalvehicle_remaining_weight
                        }
                        vehiclelist.append(datadict)

                    
                    # vehiclelist = [{"id": data.id,
                    # "vehiclename": data.vehiclename,
                    # "phone": data.phone,
                    # "remainingweight": [ delivery_order.weight for delivery_order in ordersdelivery.objects.filter(vehicle_id=data.id,user_id=data.userid.id,is_deleted=0)], 

                    # "maxorders": data.maxorders,
                    # "weightcapacity": data.weightcapacity,
                    # 'userid': data.userid.id,
                    # 'created_at': data.created_at,
                    # 'password': data.password}
                    #  for data in vehicleobj]
                    # print("---------",vehiclelist)
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
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class is_vehicle_free(APIView):
    def post(self,request):
        try:
            serializer_data  = is_vehicle_free_serializers(data=request.data)
            if serializer_data.is_valid():
                vehicle_id = serializer_data.data.get('vehicle_id')
                type = serializer_data.data.get('type')
                is_vehicle_free = ordersdelivery.objects.filter(vehicle_id=vehicle_id,status='Pending')
                if not len(is_vehicle_free) and type=='Free':
                    obj = vehicleinfo.objects.get(id=vehicle_id)
                    obj.is_vehicle_not_available=0
                    obj.save()
                    status_code=200
                    status="Success"
                    message = "You are free to pick new orders"
                else:
                    status_code=404
                    status="Fail"
                    message = "Dilever all order first"
            else:
                    status_code=300
                    status="Fail"
                    message = "data is Not valid"
            json_data = {
                'status_code': status_code,
                'status': status,
                'messgae': message,
                }
            return Response(json_data, status  = status_code)   

        except Exception as e:
            print(e)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{e}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

class clear_data(APIView):
    def post(self,request):
        try:
            data = request.data
            id = data['id']
            request_url = request.build_absolute_uri()
            slice=2
            if 'https' in request_url:
                return Response("fail",status.HTTP_400_BAD_REQUEST)
            port = request_url.split(':')[slice]
            port = port[0:4]
            print(port)
            print(id)
            if port=='8000':
                id = int(id)
                a=vehicleinfo.objects.filter(userid=27)
                print(a)
                a.update(is_vehicle_not_available=0)
                print(a)   
                a=ordersdelivery.objects.filter(user_id=27)
                print(a) 
                a.delete()
                print(a)
                return Response("Success", status.HTTP_200_OK)
            else:
                return Response("Fail", status.HTTP_400_BAD_REQUEST )
        except Exception as e:
            print(e)
            return Response("Fail", status.HTTP_500_INTERNAL_SERVER_ERROR)




class AddBranchesAPI(APIView):
    # permission_classes = [IsAuthenticated]
    # Handling Post Reuqest
    def post(self, request):
        try:
            serializer = GetSlotListSerializer(data=request.data)
            if serializer.is_valid():
                usercordiantes = User.objects.filter(id=serializer.data.get(
                        'userid', '')).exists()
                print("======22222",usercordiantes)
                if usercordiantes:
                    # data=zohoaccount.objects.get(userid=serializer.data.get(
                    #     'userid', ''),is_deleted=0)
                    # print("===========",data.refreshtoken)
                    parameters = {
                    # "refresh_token":data.refreshtoken,
                    # "refresh_token":"1000.25a090d5c14fadc4b1084d05556d077e.289204add6d03719a38814aa6c917ac6",
                    "refresh_token":"1000.18dbbc8aeb1c86231d317882035fd4ba.6fb716064eb7baa1ca994b80faa337cb",
                    # "client_id":data.clientid,
                    # "client_id":'1000.6CUWGWRSYBPGDHV0DG1L27R4M51WHX',
                    "client_id":'1000.KNTTWIQG6BRID6XQGEURG025O51XXD',
                    # "client_secret":data.clientsecret,
                    # "client_secret":'6d8f85d3802ba38fd768a37c608a0ac30acbf6e730',
                    "client_secret":'c7a0541ea8b37ea7716dc368d393fdab5f11891ae1',
                    # "redirect_uri":data.redirecturi,
                    "redirect_uri":'https://www.onlinethela.online/add-access',
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
                        
                        response = requests.get("https://books.zoho.in/api/v3/branches?organization_id=60018155668", headers=headers)
                        print("llll ",response)
                        if response.status_code == 200:
                            data =   response.json()
                            message='Iitem not found'
                            # print("dkkkkkkk : ",data)
                            # print(";;;;;;; ",data)
                            for d in data.get("branches"):
                                print("Branches list data : ",d.get('branch_id'))
                                message='All branches already exist'
                                # check item id
                                already=Branches.objects.filter(zoho_branch_id=d.get('branch_id'))
                                
                                if not already:
                                    zohodata = Branches.objects.create(
                                        branch_name=d.get('branch_name'),
                                        zoho_branch_id=d.get('branch_id'),
                                        branch_email=d.get('email'),
                                        created_at=datetime.now(),
                                        is_deleted=0,
                                        updated_at=datetime.now(),
                                    )
                                    zohodata.save()
                                    message="branches added"
                                
                            
                            json_data = {
                                'status_code': 201,
                                'status': 'Success',
                                'data':'',
                                'message': message
                            }
                            return Response(json_data, status.HTTP_201_CREATED)
                        else:
                            json_data = {
                                    'status_code': 400,
                                    'status': 'Success',
                                    'data':'',
                                    'message': "{}".format(response)
                                }
                            return Response(json_data, status.HTTP_400_BAD_REQUEST)
                    else:
                            json_data = {
                                    'status_code': 400,
                                    'status': 'Success',
                                    'data':'',
                                    'message': "{}".format(response)
                                }
                            return Response(json_data, status.HTTP_400_BAD_REQUEST)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'User not found',
                        'message': 'data not found'
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
                'error': "{}".format(err),
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
