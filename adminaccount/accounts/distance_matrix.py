# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import pandas as pd
import numpy as np
import utm
import re

class coordinates_preprocesing:
    def __init__(self,coordinates):
        # coordinate_data.columns=['customer_name','coordinates']        
        self.coordinates=np.array(coordinates)

    def clean_coordinates(self,s):

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
    def checkcoordinate(self,s):    
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
    
    def cleaned_coordinates(self):
        return np.array([self.clean_coordinates(x) for x in self.coordinates])
    def convert_to_xy(self):
        return np.array([utm.from_latlon(cor[0],cor[1])[:2] for cor in self.cleaned_coordinates()])

class distance_matrix(coordinates_preprocesing):
    def __init__(self,coordinates):
        super().__init__(coordinates)
    def euclidean_matrix_raw(self):
        xy=self.convert_to_xy()
        k = (np.array(xy) * np.ones_like(np.array(xy), shape=(len(xy), len(xy), 2))).T
        kx, ky = k[0], k[1]
        A = np.sqrt(np.add(np.square(kx-kx.T),np.square(ky-ky.T)))
        return A.astype(int)




