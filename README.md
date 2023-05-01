# MasterThesisNetworkAnalysis
All the code related to my Master Thesis (Master in Cybersecurity)

--> Master organised by the ULB with RMA, UCLouvain, UNamur, HEB, HELB

Subject : "Simulate realistic background traffic in a Cyber Range"

Promotor : Prof. Wim Mees (RMA)
Co-promotor : Prof. Georgi Nikolov (RMA)

Author : Adrien Defer

WORKING PRINCIPLE :

The Information Extraction scipt takes one or more pcap files, it extracts the main information and create :
  - <User MAC address>-Statistics.json -> All the characteristics of the Internet user with the corresponding MAC address
  - Global-Statistics.json -> All the charactéristics global independant from the users
  
 The Information Spreading script takes one <User MAC address>-Statistics.json file and generate a timeline file usable within the GHOSTS framework
 
 The groups.json file is required to run the Information Spreading script. It includes all the groups to which all the websites that have been contacted in the previously analysed pcaps files belong and which will be contacted when generating traffic.
