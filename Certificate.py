'''
Created on 19 sept. 2017

@author: bellocch
class factory design
multi inheritance
'''

import sys
import six
import abc
from time import   strftime, localtime
from subprocess import call #, STDOUT
from OpensslConfig import OpensslConfig

@six.add_metaclass(abc.ABCMeta)
class CertiticateOrigin(object):
    '''
    mother class for certificate
    common features for managing certificate will be proposed in the mother class
    abstract functions are set, shall be implemented in child
    use it to create root, intermediate and device class
    '''
    def __init__(self, trackingobject):
        '''
        Constructor needs a tracking object to be set in parameter
        when creating child class, please do
        ---> define type
        ---> define a config file
        ---> define suffixextension
        
        --> mainly define abstract method, otherwise you will have problems      
        '''     
        # define the hash to use when generating certificate
        self.hash                       = OpensslConfig.defaulthash
        # length of the modulus in 2017 2048 bit is fair 
        self.rsalength                  = OpensslConfig.defaultrsalength
        # supported hash
        self.hashlist                   = [ 'sha1', 'sha256']
      
        # give a name to the certificate
        #self.name               = OpensslConfig.undefined
        # rsa key of the object 
        self.rsakeyname                 = OpensslConfig.undefined
        # easy
        self.csrname                    = OpensslConfig.undefined
        # easy
        self.certificatename            = OpensslConfig.undefined
        # password to protect the private key of the object
        self.password                   = OpensslConfig.password  # default password
        # object that will store the generated credentials 
        self.tracking                   = trackingobject
                # type of the certificate root, intermediate, device, shall be set in child class
        self.type                       = OpensslConfig.undefined
                
        try:
            self.typelist               = self.tracking.GetTypeList()
        except: 
            print ("error in getting type list from object tracking" + sys._getframe().f_code.co_name)     
                
        # used when the certificate is signed by an authority, root or an intermediate
        self.issuerrsakeyname           = OpensslConfig.undefined
        # easy
        self.issuercertificatename      = OpensslConfig.undefined
        # password of the issuer rsa key used to sign the object
        self.issuerpassword             = OpensslConfig.undefined
        # configuration file
        self.configfile                 = OpensslConfig.undefined
        
        # extension name for the certificate; example RootCertificate.pem
        self.certificatesuffixextension = OpensslConfig.undefined        
       
    def GetRSAKeyLength(self):
        return self.rsalength
           
    def GetCSR(self):
        return self.csrname           
       
    def SetCertificate(self, line): 
        self.certificatename = line
        
    def GetCertificate(self): 
        return self.certificatename 
       
    def SetIssuerPassword(self, inissuerpassword):    
        self.issuerpassword  =   inissuerpassword
       
    def GetIssuerPassword(self):    
        return self.issuerpassword  
        
    def GetIssuerRSAKey(self):    
        return self.issuerrsakeyname   
 
    def SetIssuerRSAKey(self, line):    
        self.issuerrsakeyname  = line  
     
    def GetIssuerCertificate(self):    
        return self.issuercertificatename  
 
    def SetIssuerCertificate(self, line):    
        self.issuercertificatename  = line  
        
    def GetCertificateSuffixExtension(self):
        return   self.certificatesuffixextension         
    
    @abc.abstractmethod    
    def SetCertificateSuffixExtension(self, incertsufex):
        """extension to complete the name of the certificate"""
        #self.certificatesuffixextension = incertsufex 
        raise NotImplementedError           
    
    def IsRoot(self):
        """
        determine if the object is a root certificate
        """
        if(self.GetType() == self.typelist[0] ):
            return True
        else:
            return False
    
    def GetHash(self):
        return   self.hash         
        
    def SetHash(self, inhash):
        """default hash is sha256"""
        self.hash = inhash 

    def GetConfigFile(self):
        """ selected configuration parameters for CSR and certificate, depends on certificate type """ 
        return   self.configfile
    
    @abc.abstractmethod
    def SetConfigFile(self, infile):
        """ abstract method, get configuration parameters for CSR and certificate, depends on certificate type """       
        #self.configfile    = infile
        raise NotImplementedError
        
    def GetType(self):
        return   self.type         
     
    @abc.abstractmethod
    def SetType(self, intype):
        """type shall be part of the typelist"""
        #self.type = intype        
        raise NotImplementedError        
        
    def GetPassword(self):
        """ selected password for calculation """ 
        return   self.password
    
    def SetRsaKey(self, inkey):
        """ set rsakeyname for certificate """        
        self.rsakeyname    = inkey    
  
    def GetRsaKey(self):
        """  """ 
        return   self.rsakeyname
    
    def SetPassword(self, inpassword):
        """ set password for calculation for rsa private key encryption """        
        self.password    = inpassword 
                            
    def GenRSAkey (self):
        """ only 2048 bit RSA key is allowed
            the rsakeyname is build from the type of certificate, name of the session, date and time
        """  
        try:           
            self.rsakeyname = OpensslConfig.outputdir + "\\"   + self.GetType() +  OpensslConfig.rsakeyshortname  + "_" + self.tracking.GetSession() + "_" + strftime("%Y_%m_%d_%H_%M_%S", localtime())  + ".pem"
        except:
            print ("error while tracking command in function GenRSAkey when creating rsakey name variable " + "in" + sys._getframe().f_code.co_name)       
                
        cmd = OpensslConfig.executable + " genrsa" + " -aes128" + " -passout pass:" + self.GetPassword() + " -out "  + self.GetRsaKey() + " " + self.GetRSAKeyLength() 
   
        call(cmd, shell=False)
        try:
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.GetRsaKey())
        except :    
            print ("error while tracking command in function GenRSAkey : " + cmd + "in" + sys._getframe().f_code.co_name)   
                                                     
    def RSAkeyinClear(self):
        """  decrypt RSA key need password 
        self.password is used as it is set in constructor to the default value
        """            
        cmd = OpensslConfig.executable + " rsa" + " -passin pass:" + self.GetPassword() + " -in " + self.GetRsaKey() + " -out "  + self.GetRsaKey() +  OpensslConfig.cleartext
        #print ("genrsakey cmd is" + cmd)      
        call(cmd, shell=False)
        try:
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.GetRsaKey())
        except :    
            print ("error while tracking command in function RSAkeyinClear : " + cmd + "in" + sys._getframe().f_code.co_name)    

    def GenCSR(self, line):   
        """ create signing request from RSA key, any input parameters avoid the use of the config file, parameters of the csr will be done using cli""" 
        if( self.rsakeyname != OpensslConfig.undefined):

            self.csrname = self.GetRsaKey() + OpensslConfig.signingrequestextension
            if line == "manual":
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.GetRsaKey() + " -passin pass:" + self.GetPassword()  + " -out "  +  self.GetCSR() 
            else:
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.GetRsaKey() + " -passin pass:" + self.GetPassword() + " -out "  +  self.GetCSR() + " -config " + self.GetConfigFile()
            
            #print("cmd:", cmd)
            call(cmd, shell=False)
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.GetCSR())
            #OpensslTracking().Add("do_GenCSR:: " +  self.csrname + "\n")
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "RSA key shall be generated or select before creating the certificate signing request")
       
       
    def GenerateCommandforIntermediateorDevice(self,line):
        """
        create a command line to generate intermediate or device certificate
        shall be signed by a root authority
        certificatename has bee nbuilt by the callee
        """
        if line == "manual":
            cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.GetCSR() + " -CAcreateserial " +  " -passin pass:" + self.GetIssuerPassword() + " -CAkey " + self.GetIssuerRSAKey()  +  " -CA "  + self.GetIssuerCertificate() +  " -" + self.GetHash()  + " -out " +  self.GetCertificate() 
        else:
            cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.GetCSR() + " -CAcreateserial " +  " -passin pass:" + self.GetIssuerPassword() + " -CAkey " + self.GetIssuerRSAKey()  +  " -CA "  + self.GetIssuerCertificate() +  " -" + self.GetHash() + " -extensions v3_req -extfile "  + self.GetConfigFile() + " -out " +  self.GetCertificate() 
        return cmd       
       
    def GenCertificate(self, line):   
        """ create certificate using CSR and RSA key""" 
        if( (self.GetRsaKey() != OpensslConfig.undefined) and (self.GetCSR() !=OpensslConfig.undefined) ):

            self.certificatename = self.GetRsaKey() + "_" + self.GetType() + OpensslConfig.certificateextension
            # prepare by default a command for a root certificate 
            if line == "manual":
                cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.GetCSR() + " -signkey " + self.GetRsaKey() + " -passin pass:" + self.GetPassword() + " -" + self.GetHash()  + " -out " +  self.GetCertificate()        
            else:
                cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.GetCSR() + " -signkey " + self.GetRsaKey() + " -passin pass:" + self.GetPassword()  + " -" + self.GetHash() + " -extensions v3_req -extfile "  + self.GetConfigFile() + " -out " +  self.GetCertificate()         
            #print("cmd:", cmd)
            #call(cmd, shell=False, stderr=STDOUT)
            if (self.IsRoot()): # test if the object owns a type root
                call(cmd, shell=False)
            else: # not a root type, so specific cmd line is required to sign the certificate
                call( self.GenerateCommandforIntermediateorDevice(line), shell=False)
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.GetCertificate())
            self.CertificateToText()
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "RSA key and certificate signing request  shall be generated or select before creating the certificate")            
             
    def CertificateToText(self):   

        """ write a text version of the PEM certificate """ 
                                
        cmd = OpensslConfig.executable + " x509 " + " -in " + self.GetCertificate() + " -text " # +  self.certificatename + OpensslConfig.humanreadableextension
        try:
            file = open(self.certificatename + OpensslConfig.humanreadableextension, 'w')
        except IOError:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, self.GetCertificate() + OpensslConfig.humanreadableextension)
        else:            
            call(cmd, shell=False, stdout=file)
            file.close()
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.GetCertificate() + OpensslConfig.humanreadableextension)      
                            