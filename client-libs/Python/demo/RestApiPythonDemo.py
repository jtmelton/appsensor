'''
 AppSensor's REST Web Services demo. 
 These sample code uses the AppSensor RestApi Java client libraries.  
 The "swagger_client-1.0.0-py3.5.egg" file or similar generated one should be accessible in the build path.
 More information can be found at: client-libs/readme.md
 
@author Mahmoud Mohammadi (mahmood.mohamadi@gmail.com) 

'''

import time
import datetime
import sys

import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint
from swagger_client.models import *

def getServerConfiguration(api_instance):
    config = api_instance.resource_rest_reporting_engine_get_server_configuration_as_json_get()
    pprint(config)

def get_events(api_instance):    
    
    # Get the events added after the time indicated by the "earliest" parameter 
    events= api_instance.resource_rest_reporting_engine_find_events_get(
                    earliest = '2016-08-02T14:00:00.05Z')
    pprint(events)

def add_event(): 
    
    event = json_event.JsonEvent()
    
    #Setting the user name related to the event
    user =json_user.JsonUser() 
  
    user.username = 'Sample User'
   
    #  IP address of the source of the event
    ip= json_ip_address.JsonIPAddress()
    ip.address ='8.8.8.8'   
        
    location= json_geo_location.JsonGeoLocation()
    location.latitude=37.596758   
    location.longitude=-121.647992
      
    ip.geo_location= location
    user.ip_address =ip
         
    detection_system= json_detection_system.JsonDetectionSystem()
    
    detection_point  = json_detection_point.JsonDetectionPoint()
    detection_point.label ='Input Validation'
    detection_point.category ="IE1"
         
    event.detection_point= detection_point
    event.detection_system =detection_system 
    
    event.user=user
       
    # Setting the current time as the time of the Event
     
    utc_datetime =datetime.datetime.utcnow()
    event.timestamp =utc_datetime  
        
    # Calling the corresponding REST API web service to add the event 
    api_handler = swagger_client.RestRequestHandlerApi()
    try:
    
        api_handler.resource_rest_request_handler_add_event_post(body = event)
    
    except:
        e = sys.exc_info()[0]
        print(e)
    
def main():
    api_instance = swagger_client.RestReportingEngineApi()
    
    
    # Setting the AppSensor custom header
    api_instance.api_client.set_default_header('X-Appsensor-Client-Application-Name2','myclientapp')
    
    # Setting the base address and path of web services's server 
    api_instance.api_client.host = 'http://localhost:8085'
       
    # Calling the web service to get the server configuration    
    getServerConfiguration(api_instance)
    
    # Calling the web service to add a new Event
    add_event()

    # Calling the web service to get the recent events
    get_events(api_instance)


main()
    


    