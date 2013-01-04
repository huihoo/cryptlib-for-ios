//
//  ViewController.m
//  crytest
//
//  Created by Wang Xiaoyang on 11/26/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "ViewController.h"
#import "cryptlib.h"



@implementation ViewController

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle

- (void)viewDidLoad
{
    [super viewDidLoad];
    int status =  cryptInit(); 
   //以下方法弃用 
//  //  CRYPT_ENVELOPE cryptEnvelope;  
//    CRYPT_SESSION  cryptSession;
//    CRYPT_CONTEXT  privateKey;
//	CRYPT_CERTIFICATE cryptCertificate;
//
//    NSLog(@"cryptInit status:%d--%d",status,(int)cryptSession);
//    status =  cryptCreateSession(&cryptSession, CRYPT_UNUSED, CRYPT_SESSION_SSL) ;
//    NSLog(@"cryptCreateSession status:%d--%d",status,(int)cryptSession );
//  //  NSString *test = @"https://mows.paopaoit.com";
//   
//   status = cryptCreateCert( &cryptCertificate, CRYPT_UNUSED,CRYPT_CERTTYPE_CERTIFICATE ); 
//
//    cryptSetAttributeString( cryptCertificate, CRYPT_CERTINFO_COMMONNAME,
//                            "219.143.68.91", 13 );
//    
//    status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_SERVER_NAME, "219.143.68.91", 13 );
//    NSLog(@"cryptSetAttributeString status:%d--%d",status,(int)cryptSession );
//   
////    status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
////                      privateKey );
////    NSLog(@"cryptSetAttribute status:%d--%d",status,(int)cryptSession );
//
//    status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 1 );
//    NSLog(@"cryptSetAttribute status:%d--%d",status,(int)cryptSession );
//    
//
//     status = cryptEnd();
//     NSLog(@"cryptEnd status: %d",status);
    
    //新的方式尝试
    CRYPT_CONTEXT pubKeyContext, cryptContext; 
    void *encryptedKey; 
    int encryptedKeyLength;
    /* Generate a key */ 
    status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_3DES ); 
    status = cryptGenerateKey( cryptContext );
    
    
    CRYPT_CERTIFICATE cryptCertificate;
    /* Create a simplified certificate */ 
    status = cryptCreateCert( &cryptCertificate, CRYPT_UNUSED,CRYPT_CERTTYPE_CERTIFICATE ); 
    cryptSetAttribute( cryptCertificate, CRYPT_CERTINFO_XYZZY, 1 );
    /* Add the public key and certificate owner name and sign the certificate with the private key */

    status = cryptSetAttribute( cryptCertificate, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
    status = cryptSetAttributeString( cryptCertificate, CRYPT_CERTINFO_COMMONNAME, "219.143.68.91", 13 );
    status = cryptSignCert( cryptCertificate, cryptContext );

    UIWebView *myweb  = [[UIWebView alloc] initWithFrame:CGRectMake(20, 20, 100, 350)];
    myweb.delegate =self;
    NSURL * url = [NSURL URLWithString:@"https://219.143.68.91"];
    
    NSMutableURLRequest *request =[NSMutableURLRequest requestWithURL:url];
   //request.delegate = self;
    
    [myweb loadRequest:request];
    [self.view addSubview:myweb];
    
    

}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType{
    
    
    NSLog(@"shouldStart");
    return YES;

}
- (void)webViewDidStartLoad:(UIWebView *)webView{
    NSLog(@"StartLoad");

}
- (void)webViewDidFinishLoad:(UIWebView *)webView{
    NSLog(@"FinishLoad");

}
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error{
        NSLog(@"error:%@",error);


}
//忽略未知证书的Delegate
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    NSArray *trustedHosts;
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        if ([trustedHosts containsObject:challenge.protectionSpace.host])
            [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    
    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
}


- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated
{
	[super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated
{
	[super viewDidDisappear:animated];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

@end
