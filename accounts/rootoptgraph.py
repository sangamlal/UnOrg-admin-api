# Importing libraries
import matplotlib.pyplot as plt
import numpy as np
import math
from datetime import datetime
import utm
import re
import random

def change_coordinates(s):

        # print(s," ", s.split(' '))
        if len(s.split(' ')) == 2:
            return [float(s.split(' ')[0]), float(s.split(' ')[1])]
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
        return [n1, n2]

def plot_vehicle_graph(vehiclelist_with_coordinates):
    try:
        fig = plt.figure(figsize=(15, 4))
        fig, ax = plt.subplots()
        for onevehicledata in vehiclelist_with_coordinates:
            #Define all required list for ploting data on graph
            latitude=[]
            longitude=[]
            locationName=[]
            orderweight=[]
            deliverynumber=[]
            count=0
            for coordata in onevehicledata.get("data"):
                #Spliting latitude and longitude
                cdata=coordata.get('Coordinates').split(" ")
                namedata =coordata.get('customername')
                #cdata[0] is latitude and cdata[1] is longitude 
                try:
                    utm.from_latlon(float(cdata[0]),float(cdata[1]))
                except:
                    cdata=change_coordinates(coordata.get('Coordinates'))

                #Convert latitude and longitude in x , y coordinates
                utmdata=utm.from_latlon(float(cdata[0]),float(cdata[1]))
                # print(utmdata[0]-499618.45177441527,"----------",utmdata[1]-2971196.6812211405,"=============  ",cdata,"     :   Name : ",namedata)
                #Add latitude in list
                latitude.append(utmdata[0])
                #Add longitude in list
                longitude.append(utmdata[1])
                #Add Customer Name in list
                locationName.append(coordata.get('customername'))
                orderweight.append(coordata.get('weight'))
                #Add count in list
                deliverynumber.append(count)
                #Increment count each time by 1
                count+=1
            #Ploting x,y coordinates in graph
            ax.plot(longitude,latitude  , label='quadratic',marker="o", markersize=3.6, markeredgecolor="tomato", markerfacecolor="tomato") 
            vahiclenumber=1
            
            #Ploting Customer name on Each points
            for ydata,xdata,orderweight in zip(longitude,latitude,orderweight):
                plt.text(ydata,xdata,orderweight,va='center', ha='left',fontsize = 7)
                # plt.stem(ydata,xdata,markerfmt ='D',use_line_collection = True,linefmt ='grey')
                vahiclenumber+=1
        ax.set_xlabel('x label')  # Add an x-label to the axes.
        ax.set_ylabel('y label')  # Add a y-label to the axes.
        ax.set_title(label="Vehicle Root", fontsize=20, color="green")  # Add a title to the axes.
        ax.get_xaxis().set_visible(False)#hide x-axis
        ax.get_yaxis().set_visible(False)#hide y-axis
        #Generating Dynamic Path Dir--------- 
        dynamiclocationpath='warehousename_'+str(random.randint(1,99))+"_"+str(datetime.now())+"_graph.png"
        basedir='/home/ubuntu/rootopt/static/warehouses_graph/'
        fulldynamicpathvar=dynamiclocationpath.replace(" ",'').replace("-","_").replace(":","_").replace(".","_")
        fullpath=basedir+fulldynamicpathvar
        plt.savefig(fullpath,dpi=160) # Saving Graph Image
        return fulldynamicpathvar+".png"
    except Exception as err:
        return f'{err}'