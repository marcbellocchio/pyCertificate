'''
Created on 19 oct. 2017

@author: bellocch
child class of Certificate
implement generation of root certificate
'''

import cmd
import sys
from OpensslConfig          import OpensslConfig
from Certificate            import CertiticateOrigin


class CertificateRoot(cmd.Cmd, CertiticateOrigin):
    """
    input: pstdin is the input to use from main process
           trackingobject is the tracking class from main used to cache object
    """
    prompt = 'Root>>: '

    def __init__(self, pstdin, trackingobject ):
        #calling mother class constructor   
        cmd.Cmd.__init__(self, stdin=pstdin)      
        
        if pstdin is not None:
            # Disable rawinput module use when stdin is a script
            self.use_rawinput   = False
        #calling mother class constructor 
        CertiticateOrigin.__init__(self, trackingobject)
        # set metadata to generate a root certificate
        self.SetType(self.typelist[0])
        self.SetCertificateSuffixExtension(OpensslConfig.rootcertificateextension)
        self.SetConfigFile(OpensslConfig.configfileroot)
        
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
        """ create certificate """ 
        self.GenCertificate(line)

    def do_GenRSAkey (self, line):
        self.GenRSAkey()
    
    def do_RSAkeyinClear(self, line):
        self.RSAkeyinClear()
    
    def do_SelectRSAkey(self, line):
        """  select a  RSA key from disk, this function accepts a key file as input """
        if ( not(str(line).isspace())  ):    
            self.SetRsaKey(line) 
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)

    def do_SetPassword(self, line):
        """  set the password for the root rsa key
             optional as te default password is in the configuration file 
        """
        self.SetPassword(line)
      
        
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
        