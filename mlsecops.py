#!/usr/bin/env python
# coding: utf-8

# In[54]:


import pandas as pd


# In[55]:


dataset = pd.read_csv('/mlsecops/logs.csv', names=['IP','Web_Code'])


# In[56]:


dataset.head(5)


# In[57]:


dataset=dataset.dropna()


# In[60]:


dataset = dataset.groupby(['IP','Web_Code']).Web_Code.agg('count').to_frame('Count').reset_index()


# In[61]:


dataset.head(5)


# In[62]:


dataset.insert(0, 'SNo', range(len(dataset)))


# In[63]:


dataset.head(5)


# In[64]:


train_data = dataset.drop(['IP'], axis=1)


# In[65]:


from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
scaled_data = sc.fit_transform(train_data)


# In[66]:


from sklearn.cluster import KMeans


# In[67]:


model = KMeans(n_clusters=4)


# In[68]:


pred=model.fit_predict(scaled_data)


# In[69]:


data_with_pred = pd.DataFrame(scaled_data, columns=['IP_Scaled', 'Web_Code_Scaled','Count_Scaled'])
data_with_pred['Cluster'] = pred
final_data = pd.concat([dataset, data_with_pred], axis=1, sort=False)


# In[75]:


final_data


# In[77]:


cluster_to_block = []
for index, row in final_data.iterrows():
    if final_data['Count'].loc[index] > 100:
          cluster_to_block.append(final_data['Cluster'].loc[index])
cluster_to_block = max(set(cluster_to_block), key = cluster_to_block.count)


# In[78]:


import numpy as np
from os import system


# In[79]:


Block_IP_data = pd.read_csv('/mlsecops/DoS.csv') 
for index_in_data, row_in_data in final_data.iterrows():
    if final_data['Cluster'].loc[index_in_data] == cluster_to_block:
        if final_data['IP'].loc[index_in_data] not in np.array(Block_IP_data['Block_IP']):
                Block_IP_data = Block_IP_data.append({'Block_IP' : final_data['IP'].loc[index_in_data], 
                                                  'Status':'No'},ignore_index=True)              


# In[80]:


for index, row in Block_IP_data.iterrows():
    if Block_IP_data['Status'].loc[index] == 'No':
        system("iptables -A INPUT -s {0} -j DROP".format(Block_IP_data['Block_IP'].loc[index]))
        Block_IP_data['Status'].loc[index] = 'Yes'


Block_IP_data.to_csv('/mlsecops/DoS.csv', index=False)


# In[ ]:




