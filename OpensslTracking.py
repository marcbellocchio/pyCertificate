'''
Created on 7 sept. 2017

@author: bellocch
'''

#from time import gmtime, strftime
from OpensslConfig import OpensslConfig
import logging
#from subprocess import STDOUT, PIPE
#from OpensslConfig import OpensslConfig
#from OpensslTracking import OpensslTracking



class FoundOne(Exception): pass
"""
foundone is an object to use in exception to exit from a nested loop
"""


class OpensslTracking(object):
    '''
    keep trace of user actions during generation of certificates
    '''
    session = "undefined" 
    def __init__(self):
        '''
        Constructor
        '''
        #self.session = "undefined"
        self.objecttype             = [ 'Root', 'Intermediate', 'Device']
        self.cache                  = []
        self.file                   = "none"  
        
        logging.basicConfig(level=logging.INFO,
                        filename=OpensslConfig.logfile, filemode='a',
                        format='%(name)-28s %(levelname)-10s %(message)s')
          
    def GetLogger(self, classobject):
        self.loggername = '.'.join([classobject.__class__.__name__])
        return logging.getLogger(self.loggername)
        
    def GetTypeList (self):
        return    self.objecttype 
               
    def SetInfo(self, classobject, functionname, message):
        '''
        Info level, 
        class object to get the name of the class calling the log file,
        function name to identify the name of the function calling log
        message is the text 
        '''        
        self.logger = self.GetLogger(classobject)
        self.GetLogger(classobject).info(": "  + str(functionname).ljust(OpensslConfig.stringtrailingpadding) + "\t\t" + message)
        
    def SetWarning(self, classobject, functionname, message):
        self.logger = self.GetLogger(classobject)
        self.GetLogger(classobject).warning(": "  + str(functionname).ljust(OpensslConfig.stringtrailingpadding) + "\t\t" + message)
        
    def SetError(self, classobject, functionname, message):
        self.logger = self.GetLogger(classobject)
        self.GetLogger(classobject).error(": "  + str(functionname).ljust(OpensslConfig.stringtrailingpadding) + "\t\t" +  message)
                    
    def SetSession(self, text):
        self.session = text

    def GetSession(self):
        return self.session

    def AddToCache(self, objecttocache):   
            self.cache.append(objecttocache)
            
    def GetFromCache (self, intype):
        """
        try to find in the cache an object with requested type
        """
        found = None
        try:
            for fname in self.objecttype:
                if fname.startswith(intype):
                    #requested name if known
                    for fobject in self.cache:
                        if fobject.type.startswith(intype):
                            raise FoundOne("object found in cache" + intype)
        except FoundOne:
            found= fobject
        finally:
            return found            
    """
    def GetFromCache (self, objectname):
        found = None
        try:
            for fname in self.objecttype:
                if fname.startswith(objectname):
                    #requested name if known
                    for fobject in self.cache:
                        if fobject.name.startswith(objectname):
                            raise FoundOne("object found in cache")
        except FoundOne:
            found= fobject
        finally:
            return found
     """       
    #def GetSession(self):

        
                