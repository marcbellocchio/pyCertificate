'''
Created on 19 sept. 2017

@author: bellocch
'''

import sys
from subprocess import call #, STDOUT
from OpensslConfig import OpensslConfig


class MyClass(object):
    '''
    classdocs
    mother class for certificate
    '''


    def __init__(self, trackingobject):
        '''
        Constructor
        '''
        
        self.hash               = OpensslConfig.defaulthash
        self.rsalength          = OpensslConfig.defaultrsalength
        self.hashlist           = [ 'sha1', 'sha256']
        self.type               = OpensslConfig.undefined
        self.name               = OpensslConfig.undefined
        self.rsakeyname         = OpensslConfig.undefined
        self.csrname            = OpensslConfig.undefined
        self.certificatename    = OpensslConfig.undefined
        self.password           = OpensslConfig.password  # default password 
        self.tracking           = trackingobject
        
        # used when the certificate is not from a type root
        self.issuerrsakeyname         = OpensslConfig.undefined
        self.issuercertificatename    = OpensslConfig.undefined
        

    def GetHash(self):
        return   self.hash
    
    def SetHash(self, inhash):
        self.hash    = inhash
        
        
    def CertificateToText(self):   
        """ txt version of the PEM certificate """ 
                                
        cmd = OpensslConfig.executable + " x509 " + " -in " + self.certificatename + " -text " # +  self.certificatename + OpensslConfig.humanreadableextension
        try:
            file = open(self.certificatename + OpensslConfig.humanreadableextension, 'w')
        except IOError:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)
        else:            
            call(cmd, shell=False, stdout=file)
            file.close()
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)      