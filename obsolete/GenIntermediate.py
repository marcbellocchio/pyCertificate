import  cmd
import  sys
from    subprocess import call #, STDOUT
from    time import   strftime, localtime
from    OpensslConfig import OpensslConfig
from    OpensslTracking import OpensslTracking
import  os.path


class GenIntermediate(cmd.Cmd):
    
    """
    input: pstdin is the input to use from main process
           trackingobject is the tracking class from main used to cache object
    """

    prompt = 'Intermediate>>: '

    def __init__(self, pstdin, trackingobject ):
        #get  
        super(GenIntermediate, self).__init__(stdin=pstdin)      
        self.hash                   = "sha256"
        self.rsalength              = "2048"
        self.hashlist               = [ 'sha1', 'sha256']
        self.name                   = OpensslConfig.intermediateobjectname
        self.rootrsakeyname         = OpensslConfig.undefined
        self.rootcertificatename    = OpensslConfig.undefined
        self.rsakeyname             = OpensslConfig.undefined
        self.csrname                = OpensslConfig.undefined
        self.certificatename        = OpensslConfig.undefined
        self.password               = OpensslConfig.password  # default password  
        self.usecache               = True       
        
        if pstdin is not None:
            # Disable rawinput module use when stdin is a script
            self.use_rawinput   = False
            
        self.tracking           = trackingobject
         
    def GetHash(self):
        return   self.hash     
        
    def do_GenCSR(self, line):   
        """ create signing request from RSA key, any input parameters avoid the use of the config file, parameters of the csr will be done using cli""" 
        if( self.rsakeyname != OpensslConfig.undefined):

            self.csrname = self.rsakeyname + OpensslConfig.signingrequestextension
            if line == "manual":
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -out "  +  self.csrname 
            else:
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -out "  +  self.csrname + " -config " + OpensslConfig.configfileintermediate
            
            call(cmd, shell=False)
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.csrname)
            #OpensslTracking().Add("do_GenCSR:: " +  self.csrname + "\n")
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "RSA key shall be generated or select before creating the certificate signing request")
            
        
    
    def do_GenCertificate(self, line):   
        """ create certificate signed by root
            by default check the cache to find a root certificate, once found use it 
            when the cache is empty, use the select functions to define which root shall be used 
        """  
        #C:\OpenSSL-Win32\bin\openssl.exe x509 -days 9000 -req -in "%basedir%\brandCertificate2048.csr" -CAcreateserial -passin pass:AnoMalocarys#69 -CAkey "%basedirroot%\RootTestRSAkey2048.pem"  -CA "%basedirroot%\RootTestRSAKeyCERTIF2048Signed.pem" -sha1 -extensions v3_req -extfile "%basedir%\configfileBrandCertif2048.txt" -out "%basedir%\brandCertificate2048Sha1RootSigned.pem"
        if( (self.rsakeyname != OpensslConfig.undefined) and (self.csrname !=OpensslConfig.undefined) ):
            if(self.usecache):
                cacheobject = self.tracking.GetFromCache(OpensslConfig.rootobjectname)
                try:  # try because object in cache can be corrupted
                    self.rootrsakeyname         = cacheobject.rsakeyname
                    self.rootcertificatename    = cacheobject.certificatename
                    self.tracking.SetInfo(self, sys._getframe().f_code.co_name, " getting root from cache")
                except:
                    self.tracking.SetError(self, sys._getframe().f_code.co_name, " no root in cache, please select a root manually using select functions")
                    self.rootrsakeyname         = OpensslConfig.undefined
                    self.rootcertificatename    = OpensslConfig.undefined        
                    
            if ( (self.rootrsakeyname and  self.rootcertificatename) != OpensslConfig.undefined  ):        
                self.certificatename = self.rsakeyname + OpensslConfig.intermediatecertificateextension
                if line == "manual":
                    cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.csrname + " -CAcreateserial " +  " -passin pass:" + OpensslConfig.password + " -CAkey " + self.rootrsakeyname  +  " -CA "  + self.rootcertificatename +  " -" + self.GetHash()  + " -out " +  self.certificatename 
                else:
                    cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.csrname + " -CAcreateserial " +  " -passin pass:" + OpensslConfig.password + " -CAkey " + self.rootrsakeyname  +  " -CA "  + self.rootcertificatename +  " -"  + self.GetHash() + " -extensions v3_req -extfile "  + OpensslConfig.configfileintermediate + " -out " +  self.certificatename         
                #print("cmd:", cmd)
                #call(cmd, shell=False, stderr=STDOUT)
                call(cmd, shell=False)
                self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.certificatename)
                self.tracking.SetInfo(self, sys._getframe().f_code.co_name, " root rsa key was : " + self.rootrsakeyname + "root certificate was : " + self.rootcertificatename )                
                self.CertificateToText()
            
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, " RSA key and certificate signing request  shall be generated or select before creating the certificate ")            
        
    def CertificateToText(self):   
        """ txt version of the PEM certificate """ 
                                
        cmd = OpensslConfig.executable + " x509 " + " -in " + self.certificatename + " -text " # +  self.certificatename + OpensslConfig.humanreadableextension
        try:
            file = open(self.certificatename + OpensslConfig.humanreadableextension, 'w')
        except IOError:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)
        else:            
            print("cmd:", cmd)
            call(cmd, shell=False, stdout=file)
            file.close()
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)
        #OpensslTracking().Add("do_GenCSR:: " +  self.csrname + "\n")

    def do_GenRSAkey (self, line):
        """ only 2048 bit RSA """             
        self.rsakeyname = OpensslConfig.outputdir + "\\IntermediateRSAKey" + "_" + OpensslTracking.session + "_" + strftime("%Y_%m_%d_%H_%M_%S", localtime())  + ".pem"
        cmd = OpensslConfig.executable + " genrsa" + " -aes128" + " -passout pass:" + OpensslConfig.password + " -out "  + self.rsakeyname + " " + self.rsalength 
   
        call(cmd, shell=False)
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)
        
    def do_SetPassword(self, line):
        """  set the password for the intermediate rsa key
             optional as the default password is in the configuration file 
             the password shall be set before the RSA key generation
        """
        if ( not(str(line).isspace())  ):    
            self.password = line
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.password)
                
    
    def do_RSAkeyinClear(self, line):
        """  decrypt RSA key """
                                
        cmd = OpensslConfig.executable + " rsa" + " -passin pass:" + OpensslConfig.password + " -in " + self.rsakeyname + " -out "  + self.rsakeyname +  OpensslConfig.cleartext
        #print ("genrsakey cmd is" + cmd)      
        call(cmd, shell=False)
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)
    
    def do_SelectRSAkey(self, line):
        """  select a  RSA key from disk, this function accepts a key file as input """
        if ( not(str(line).isspace())  ):    
            self.rsakeyname = line
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)

    def do_SelectHash(self, line):
        """default hash is sha256"""
        if ( (not(str(line).isspace())) and (line in self.hashlist) ):  
            if (line == self.hashlist[0] ):
                self.tracking.SetWarning(self, sys._getframe().f_code.co_name, "deprecated hash: "  + self.hashlist[0])
                self.hash = line   
            else:
                self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "hash: "  + line)
                self.hash = line   
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
        """ to exit from Intermediate class"""
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "caching object" ) 
        self.tracking.AddToCache(self)   
        return True
    
    
    """
    >>>>>>   MANAGEMENT OF ROOT CERTIFICATE AND RSA KEY
    """
    
    def do_SelectRootCertificate(self, line):   
        """ select root certificate to be used as root authority to sign intermediate certificate
            the RSA key shall be selected as well
            input is a root certificate
        """     
        if ( not(str(line).isspace())  ):    
            self.rootcertificatename        = line
            self.usecache                   = False
    
    def do_SelectRootRSAKey(self, line):   
        """ select rsa key associated to the root certificate
        """     
        if ( not(str(line).isspace())  ):    
            self.rootrsakeyname             = line
            self.usecache                   = False    
    
    def GetRSAKeyFromCertificate(self, nameofcertificate):
        """
            format :
            example:
            [name of the RSA key][name of the session][date].pem [name of the root certificate].pem
            RootRSAKey_myTest_2017_09_12_18_06_20.pem_RootCertificate.pem
        """
        # test if the file exist !
        rsakeyfromcertificate = None
        if (not (os.path.isfile(nameofcertificate)) ):
            self.tracking.SetError(self, sys._getframe().f_code.co_name, " certificate: " + nameofcertificate + " is not file " )
        else:      
            # count the number of .pem in the name when 2 get the
            try:
                if (nameofcertificate.count(OpensslConfig.pemextension) == 2):   # 2 .pem if filename
                    Listofname = list(str(nameofcertificate).split(OpensslConfig.pemextension,1))
                    if (len(Listofname) == 2):
                        rsakeyfromcertificate =  Listofname[0] + OpensslConfig.pemextension
                        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, " selecting RSA key "  + rsakeyfromcertificate + " from certificate " + nameofcertificate)
                    else:
                        self.tracking.SetError(self, sys._getframe().f_code.co_name, " RSA key cannot be selected from certificate name " + nameofcertificate)
            except:
                self.tracking.SetError(self, sys._getframe().f_code.co_name, " exception occured " + nameofcertificate)
        return rsakeyfromcertificate
        
    def do_SelectRSAkeyRootFromCertificate(self, line):   
        """ select the rsa key associated to the root certificate to sign intermediate certificate
            use this function if the root certificate naming as been changed
            The selection of the root certificate allows to automatically select the associated RSA key
            format :
            example:
            [name of the RSA key][name of the session][date].pem [name of the root certificate].pem
            RootRSAKey_myTest_2017_09_12_18_06_20.pem_RootCertificate.pem
            input is the root certificate used as a link to find the rsa key
        """ 
        if ( not(str(line).isspace() )  ):
            localname= self.GetRSAKeyFromCertificate(line)               
            if ( localname != None):
                self.rootcertificatename            = line 
                self.rootrsakeyname                 = localname   
                self.usecache                       = False          
                                      
    
    
    def do_cmdloop(self,*args):
        self.cmdloop()