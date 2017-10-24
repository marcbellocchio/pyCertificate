'''
Created on 19 oct. 2017

@author: bellocch
child class of Certificate
implement generation of intermediate  certificate
'''

import cmd
import sys
import  os.path
from OpensslConfig          import OpensslConfig
from Certificate            import CertiticateOrigin

class CertificateDevice(cmd.Cmd, CertiticateOrigin):
    """
    input: pstdin is the input to use from main process
           trackingobject is the tracking class from main used to cache object
    """
    prompt = 'Device>>: '

    def __init__(self, pstdin, trackingobject ):
        #calling mother class constructor   
        cmd.Cmd.__init__(self, stdin=pstdin)      
        
        if pstdin is not None:
            # Disable rawinput module use when stdin is a script
            self.use_rawinput   = False
        #calling mother class constructor 
        CertiticateOrigin.__init__(self, trackingobject)
        
        # by default use the cache, the idea is to get the root generated few seconds ago
        self.usecache               = True  
        # root can be a real root or an intermediate certificate is the created chain extends 3 levels
        
        # set metadata to generate an device  certificate
        self.SetType(self.typelist[2])
        self.SetCertificateSuffixExtension(OpensslConfig.devicecertificateextension)
        self.SetConfigFile(OpensslConfig.configfiledevice)
        
    def SetCacheUsage(self, use):
        """
        set the use of the cache to true or false, default is true
        """
        if (type(use) == bool):
            self.usecache   = use   
                     
    def GetCacheUsage(self):
        return self.usecache           
        
    def SetCertificateSuffixExtension(self, incertsufex):
        """extension to complete the name of the certificate"""
        self.certificatesuffixextension =incertsufex 
             
    def SetConfigFile(self, infile):
        """ abstract method, get configuration parameters for CSR and certificate, depends on certificate type """       
        self.configfile    = infile

    def SetType(self, intype):
        """type shall be part of the typelist"""
        self.type = intype               
        
    def do_GenCSR(self, line):   
        """
        generate CSR calling mother class method 
        """
        self.GenCSR(line)
        
    def do_GenCertificate(self, line):   
        """ create certificate 
            by default check the cache to find an intermediate certificate, once found use it 
            when the cache is empty, use the select functions to define which intermediate shall be used
        """ 
        
        if( (self.GetRsaKey() != OpensslConfig.undefined) and (self.GetCSR() !=OpensslConfig.undefined) ):
            if(self.usecache):
                cacheobject = self.tracking.GetFromCache(self.tracking.GetTypeList()[1])
                try:  # try because object in cache can be corrupted
                    self.SetIssuerRSAKey(cacheobject.rsakeyname)
                    self.SetIssuerCertificate(cacheobject.certificatename)
                    self.tracking.SetInfo(self, sys._getframe().f_code.co_name, " getting issuer from cache")
                    # test if issuer password has been initialised, if not set the password to current rsa key password
                    if(self.GetIssuerPassword() == OpensslConfig.undefined):
                        self.SetIssuerPassword(self.GetPassword())
                        
                except:
                    self.tracking.SetError(self, sys._getframe().f_code.co_name, " no issuer in cache, please select it manually using select functions")
                    self.SetIssuerRSAKey(OpensslConfig.undefined)
                    self.SetIssuerCertificate( OpensslConfig.undefined) 
        
        
            self.GenCertificate(line)

        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, " RSA key and certificate signing request  shall be generated or select before creating the certificate ")            
        

    def do_GenRSAkey (self, line):
        """
        generate RSA key
        """
        self.GenRSAkey()
    
    def do_RSAkeyinClear(self, line):
        """
        generate RSA key in clear
        """        
        self.RSAkeyinClear()
    
    def do_SelectRSAkey(self, line):
        """  select a  RSA key from disk for intermediate certificate, this function accepts a key file as input """
        if ( not(str(line).isspace())  ):    
            self.SetRsaKey(line) 
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)

    """
      >>>>>>   MANAGEMENT OF ISSUER CERTIFICATE AND RSA KEY
    """
    
    def do_SelectIssuerCertificate(self, line):   
        """ select root certificate or intermediate to be used as root authority to sign device certificate
            the RSA key shall be selected as well
            input is a root or CA authority certificate
            certificate shall be in pem format

        """     
        if ( not(str(line).isspace())  ):    
            self.SetIssuerCertificate(line)     
            self.SetCacheUsage(False)                 
    
    def do_SelectIssuerRSAKey(self, line):   
        """ select rsa key associated to the issuer certificate
            set the password for the key
        """     
        if ( not(str(line).isspace())  ):    
            self.SetIssuerRSAKey(line)
            self.SetCacheUsage(False)   
    
    
    def do_SelectIssuerPassword(self, line):   
        """ select rsa key password 
        """     
        if ( not(str(line).isspace())  ):    
            self.issuerpassword           = line
   
    
    def GetIssuerRSAKeyFromCertificate(self, nameofcertificate):
        """
            format : [name of the RSA key][name of the session][date].pem [name of the root certificate].pem
            example:
            RootRSAKey_myTest_2017_09_12_18_06_20.pem_RootCertificate.pem
            only full path is accepted
            used by the function do_SelectRSAkeyFromIssuerCertificate
        """
        # test if the file exist !
        rsakeyfromcertificate = None
        if (not (os.path.isfile(nameofcertificate)) ):
            self.tracking.SetError(self, sys._getframe().f_code.co_name, " certificate: " + nameofcertificate + " is not file " )
        else:      
            # count the number of .pem in the name when 2 is achieved get the whole name
            try:
                if (nameofcertificate.count(OpensslConfig.pemextension) == 2):   # 2 times .pem in filename
                    Listofname = list(str(nameofcertificate).split(OpensslConfig.pemextension,1)) # cut the string in list of string
                    if (len(Listofname) == 2):# first string is the rsa key name
                        rsakeyfromcertificate =  Listofname[0] + OpensslConfig.pemextension
                        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, " selecting RSA key "  + rsakeyfromcertificate + " from certificate " + nameofcertificate)
                    else:
                        self.tracking.SetError(self, sys._getframe().f_code.co_name, " RSA key cannot be selected from certificate name " + nameofcertificate)
            except:
                self.tracking.SetError(self, sys._getframe().f_code.co_name, " exception occured " + nameofcertificate)
        return rsakeyfromcertificate
        
    def do_SelectRSAkeyFromIssuerCertificate(self, line):   
        """ select the rsa key associated to the root, issuer certificate to sign intermediate certificate
            The selection of the root certificate allows to automatically select the associated RSA key
            format :
            example:
            [name of the RSA key][name of the session][date].pem [name of the root certificate].pem
            RootRSAKey_myTest_2017_09_12_18_06_20.pem_RootCertificate.pem
            input is the root certificate used as a link to find the rsa key
        """ 
        if ( not(str(line).isspace() )  ):
            localname= self.GetIssuerRSAKeyFromCertificate(line)               
            if ( localname != None):
                self.SetIssuerCertificate(line) 
                self.SetIssuerRSAKey(localname)   
                self.SetCacheUsage(False)                         


    def do_SetIssuerPassword(self, line):
        """  set the password for the root, issuer rsa key
             optional as the default password is in the configuration file 
        """
        self.SetIssuerPassword(line)
      
        
    def do_SelectHash(self, line):
        """default hash is sha256"""
        if ( (not(str(line).isspace())) and (line in self.hashlist) ):  
            if (line == self.hashlist[0] ):
                self.tracking.SetWarning(self, sys._getframe().f_code.co_name, "deprecated hash: "  + self.hashlist[0])
                self.SetHash(line)   
            else:
                self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "hash: "  + line)
                self.SetHash(line)      
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "Unsupported hash: "+ line + " current hash is : " + self.hash)
        
    def complete_SelectHash(self, text, line, begidx, endidx):
        if not text:
            completions = self.hashlist[:]
        else:
            completions = [ f
                            for f in self.hashlist
                            if f.startswith(text)
                            ]
        return completions        
    
    def do_exit(self,*args):
        """ to exit from Root class"""
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "caching object" ) 
        self.tracking.AddToCache(self)   
        """
        fifi = self.tracking.GetFromCache("root")
        if (fifi != None):
            print("fifi name is" + fifi.name)
        """  
        return True
    
    def do_cmdloop(self,*args):
        self.cmdloop()
        