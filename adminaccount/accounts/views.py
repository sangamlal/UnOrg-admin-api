from django.shortcuts import render
from ast import Try
import imp
import json
from operator import truediv
from select import select
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import  status
from rest_framework.response import Response
# Create your views here.
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.exceptions import APIException
from datetime import datetime
from django.core.mail import EmailMultiAlternatives
from .serializers import *
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User,zohoaccount
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.core import serializers
import requests
# Create your views here.


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
#Define Create User (Register User) API with only post request
class SignupUser(APIView):
    #Handling Post Reuqest 
    def post(self,request):
        try:
            serializer=SignupUserSerializer(data=request.data)
            if serializer.is_valid():
                user=User.objects.create(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    first_name=serializer.validated_data.get('first_name',''),
                    last_name=serializer.validated_data.get('last_name',''),
                    mobile=serializer.validated_data.get('mobile',''),
                    is_zoho_active=0
                )
                user.set_password(serializer.validated_data['password'])
                user.save()
                refresh = RefreshToken.for_user(user)
                if user:
                    json_data={
                    'status_code':201,
                    'status':'Success',
                    'username':str(user),
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'message':'User created'
                    }
                    return Response(json_data,status.HTTP_201_CREATED)
                else:
                    json_data={
                    'status_code':200,
                    'status':'Success',
                    'data':'User not created',
                    'message':'data not created'
                    }
                    return Response(json_data,status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data={
                'status_code':200,
                'status':'Failed',
                'error':serializer.errors,
                'remark':'Serializer error'
                }
                return Response(json_data,status.HTTP_200_OK)
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)
    def patch(self,request):
        try:
            # print("iiiiiiiii ",request.id)
            serializer=EditUserProfileSerializer(data=request.data)
            if serializer.is_valid():
                userinfo=User.objects.filter(id=serializer.data.get('id'))
                if userinfo:
                    
                    # print("--------------",userinfo.get("username"))
                    userinfo.update(
                        username=serializer.validated_data.get('username'),
                        email=serializer.validated_data.get('email'),
                        first_name=serializer.validated_data.get('first_name',''),
                        last_name=serializer.validated_data.get('last_name',''),
                        mobile=serializer.validated_data.get('mobile','')
                    )
                    json_data={
                    'status_code':205,
                    'status':'Success',
                    'message':'User updated successfully'
                    }
                    return Response(json_data,status.HTTP_205_RESET_CONTENT)
                else:
                    print("================")
                    json_data={
                    'status_code':204,
                    'status':'Success',
                    'message':'User not found'
                    }
                    return Response(json_data,status.HTTP_204_NO_CONTENT)
            else:
                
                json_data={
                'status_code':200,
                'status':'Failed',
                'error':serializer.errors,
                'remark':'Serializer error'
                }
                return Response(json_data,status.HTTP_200_OK)
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)
    def delete(self,request):
        try:
            # print("iiiiiiiii ",request.id)
                deletestatus,userinfo=User.objects.filter(id=request.data.get('id')).delete()
                # print(deletestatus,"--------------",userinfo)
                if deletestatus:
                    json_data={
                    'status_code':205,
                    'status':'Success',
                    'message':'User deleted successfully'
                    }
                    return Response(json_data,status.HTTP_205_RESET_CONTENT)
                else:
                    # print("================")
                    json_data={
                    'status_code':204,
                    'status':'Success',
                    'message':'User not found'
                    }
                    return Response(json_data,status.HTTP_204_NO_CONTENT)
            
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)




class UserLoginView(APIView):

  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        username = serializer.data.get('username')
        password = serializer.data.get('password')
        user = authenticate(username=username, password=password)
        data=User.objects.get(username=user)
        newdata={
            "id":data.id,
            "username":data.username,
            "email":data.email,
            "first_name":data.first_name,
            "last_name":data.last_name,
            "mobile":data.mobile,
            "is_active":data.is_active,
            "is_superuser":data.is_superuser,
            "is_zoho_active":data.is_zoho_active,
        }
        print("-----------------",newdata)
        print("-----------------",type(data))
        if user is not None:
            token = get_tokens_for_user(user)
            json_data={
                'status_code':201,
                'status':'Success',
                'data':newdata,
                'refresh': str(token.get("refresh")),
                'access': str(token.get("access")),
                'message':'User login success'
                }
            return Response(json_data,status.HTTP_201_CREATED)
            
        else:
            json_data={
                'status_code':401,
                'status':'Failed',
                'error':"User name or Password is incorrect",
                }
            return Response(json_data,status.HTTP_401_UNAUTHORIZED)
    else:
        print("I am api called-------")
        json_data={
        'status_code':200,
        'status':'Failed',
        'error':serializer.errors,
        'remark':'Serializer error'
        }
        return Response(json_data,status.HTTP_200_OK)
            
    

class SendZohoRegistrationLink_fun(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        try:
            serializer = SendZohoRegistrationLinkSerializer(data=request.data)
            if serializer.is_valid():
                print("-----------")
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
                subject, from_email, to = emailSubject, 'UnOrg <shwetanshumishra1999@gmail.com>', [serializer.data.get('email')]
                html_content = emailBody
                msg = EmailMultiAlternatives(subject, html_content, from_email, to)
                msg.attach_alternative(html_content, "text/html")
                print("Client Mail sent successfullly")
                msg.send()
                if msg:
                        json_data={
                        'status_code':200,
                        'status':'Success',
                        'message':'Email Send Successfully'
                        }
                        return Response(json_data,status.HTTP_200_OK)
                else:
                    json_data={
                    'status_code':200,
                    'status':'Failed',
                    'message':'Email not send'
                    }
                    return Response(json_data,status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data={
                'status_code':200,
                'status':'Failed',
                'error':serializer.errors,
                'remark':'Serializer error'
                }
                return Response(json_data,status.HTTP_200_OK)
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserList_fun(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            print("--------------")

            activeuserinfo=User.objects.filter(is_active=1)
            inactiveuserinfo=User.objects.filter(is_active=0)
            activeuserlist=[{"id":data.id,"username":data.username,"first_name":data.first_name,"mobile":data.mobile,"email":data.email,"first_name":data.first_name,"last_name":data.last_name} for data in activeuserinfo]
            inactiveuserlist=[{"id":data.id,"username":data.username,"first_name":data.first_name,"mobile":data.mobile,"email":data.email,"first_name":data.first_name,"last_name":data.last_name} for data in inactiveuserinfo]
            # print(list(activeuserinfo),"============",activeuserlist)
            if activeuserinfo or inactiveuserinfo:
                json_data={
                'status_code':200,
                'status':'Success',
                'activeuser':activeuserlist,
                'inactiveuser':inactiveuserlist,
                'message':'User found'
                }
                return Response(json_data,status.HTTP_200_OK)
            else:
                print("================")
                json_data={
                'status_code':204,
                'status':'Success',
                'message':'User not found'
                }
                return Response(json_data,status.HTTP_204_NO_CONTENT)
           
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetUserDetail_fun(APIView):
    def get(self,request):
        try:
            print("--------------")

            userdata=User.objects.filter(id=request.data.get("id"))
            userdetail=[{"id":data.id,"username":data.username,"first_name":data.first_name,"mobile":data.mobile,"email":data.email,"first_name":data.first_name,"last_name":data.last_name} for data in userdata]
            
            if userdetail:
                json_data={
                'status_code':200,
                'status':'Success',
                'data':userdetail,
                'message':'User found'
                }
                return Response(json_data,status.HTTP_200_OK)
            else:
                print("================")
                json_data={
                'status_code':204,
                'status':'Success',
                'message':'User not found'
                }
                return Response(json_data,status.HTTP_204_NO_CONTENT)
           
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)



class AddZohoCredential(APIView):
    #Handling Post Reuqest 
    def post(self,request):
        try:
            serializer=ZohoAccountSerializer(data=request.data)
            if serializer.is_valid():
                zohodata=zohoaccount.objects.create(
                    userid=serializer.validated_data['userid'],
                    clientid=serializer.validated_data['clientid'],
                    clientsecret=serializer.validated_data.get('clientsecret',''),
                    accesstoken=serializer.validated_data.get('accesstoken',''),
                    refreshtoken=serializer.validated_data.get('refreshtoken',''),
                    redirecturi=serializer.validated_data.get('redirecturi',''),
                    is_deleted=0,
                    created_at=datetime.now(),
                )
                zohodata.save()
                print("=========get data==",zohodata)
                #Email Send Process
                UserObj=User.objects.get(id=serializer.validated_data['userid'])
                clientid=serializer.validated_data.get('clientid','')
                redirecturi=serializer.validated_data.get('redirecturi','')
                print(redirecturi,"-------------",clientid)
                emailBody="UnOrg code : "+str(zohodata.id)+"<br>https://accounts.zoho.com/oauth/v2/auth?scope=ZohoBooks.invoices.CREATE,ZohoBooks.invoices.READ,ZohoBooks.invoices.UPDATE,ZohoBooks.invoices.DELETE&client_id="+clientid+"&state=testing&response_type=code&redirect_uri="+redirecturi+"&access_type=offline"
                emailSubject="Get Zoho Code "
                subject, from_email, to = emailSubject, 'UnOrg <shwetanshumishra1999@gmail.com>', [UserObj.email]
                html_content = emailBody
                msg = EmailMultiAlternatives(subject, html_content, from_email, to)
                msg.attach_alternative(html_content, "text/html")
                print("Client Mail sent successfullly")
                msg.send()
                serializer.validated_data['userid']
                if zohodata:
                    json_data={
                    'status_code':201,
                    'status':'Success',
                    'zohoaccount':zohodata.id,
                    'message':'Data saved'
                    }
                    return Response(json_data,status.HTTP_201_CREATED)
                else:
                    json_data={
                    'status_code':200,
                    'status':'Success',
                    'message':'Data not saved'
                    }
                    return Response(json_data,status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data={
                'status_code':200,
                'status':'Failed',
                'error':serializer.errors,
                'remark':'Serializer error'
                }
                return Response(json_data,status.HTTP_200_OK)
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)
    def patch(self,request):
        try:
            serializer=EditZohoAccountSerializer(data=request.data)
            if serializer.is_valid():
                userinfo=zohoaccount.objects.get(id=serializer.validated_data.get('id'))
                code=serializer.validated_data.get('code','')
                client_id=userinfo.clientid
                client_secret=userinfo.clientsecret
                redirect_uri=userinfo.redirecturi
                
                url = "https://accounts.zoho.in/oauth/v2/token?code="+code+"&client_id="+client_id+"&client_secret="+client_secret+"&redirect_uri="+redirect_uri+"&grant_type=authorization_code"

                payload = "\r\n  \r\n"
                headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': '6e73717622=3bcf233c3836eb7934b6f3edc257f951; _zcsr_tmp=578d48be-da9a-4183-bfc8-d98f34d13b27; iamcsr=578d48be-da9a-4183-bfc8-d98f34d13b27'
                }

                response = requests.request("POST", url, headers=headers, data=payload).json()

                print("--------------",userinfo)

                if response.get('access_token') :
                    
                    
                    userinfo.accesstoken=response.get('access_token','')
                    userinfo.refreshtoken=response.get('refresh_token','')
                    userinfo.save()
                    datauser=User.objects.filter(id=userinfo.userid)
                    datauser.update(is_active=1)
                    
                    json_data={
                    'status_code':200,
                    'status':'Success',
                    'message':'Token updated successfully'
                    }
                    return Response(json_data,status.HTTP_200_OK)
                else:
                    print("================")
                    json_data={
                    'status_code':200,
                    'status':'Success',
                    'message':response.get("error")
                    }
                    return Response(json_data,status.HTTP_200_OK)

            else:
                print("I am api called-------")
                json_data={
                'status_code':200,
                'status':'Failed',
                'error':serializer.errors,
                'remark':'Serializer error'
                }
                return Response(json_data,status.HTTP_200_OK)
        except Exception as err:
            print("Error :",err)
            json_data={
                'status_code':500,
                'status':'Failed',
                'error':err,
                'remark':'Landed in exception',
            }
            return Response(json_data,status.HTTP_500_INTERNAL_SERVER_ERROR)
