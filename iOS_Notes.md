grep for NSURLConnection, NSURLSession, NSURLCredential, dataWithContentsOfURL

grep for UIWebView, shouldStartLoadWithRequest // maybe iOS-Javascript bridge here

grep for CFNetwork // Carbon Framework

grep for "didReceiveAuthenticationChallenge", "continueWithoutCredentialForAuthenticationChallenge", "kSSLSessionOptionBreakOnServerAuth", "kCFStreamPropertySSLSettings"

grep for "SSLCipherSuite"

grep for "NSFileProtectionNone", "kSecAttrAccessibleAlways"

grep for "openURL", "handleOpenURL"

grep for "sqlite3", "sqlite3_open"

grep for "setShouldResolveExternalEntities"

grep for "CLocationManager" // GeoLocation data shouldn't be stored... If it is, check the DataProtectionLevel used

grep for "NSLog" // logging sensitive information should be avoided

grep for "UIPasteboard" // review the interaction with the generalPasteboard

## Swift:

grep for "stringWithContentsOfURL", _TFE10FoundationSSCfzT10contentsOfVS_3URL8encodingVES_SS8Encoding_SS

---

Objective-C uses a traditional message-passing system within the runtime rather than using direct function calls or making function calls via vtables for dynamic dispatch. That is, to invoke a function you pass it a message, proxying through the runtime’s objc_msgSend() function, allowing the implementation for a method to be resolved at runtime.


Class class = objc_getClass("HelloWorld");
id receiver = [[class alloc] init];
SEL selector = NSSelectorFromString(@"sayHello:");

objc_msgSend(theReceiver,theSelector, @"RUB");

---

/Applications   --> System Applications
/var/mobile/Library/AddressBook/AddressBook.sqlitedb --> Contacts Db


/var/mobile/Containers/Bundle/Application/<UUID>/Application.app/ 
/var/mobile/Containers/Data/Application/<UUID>/Documents/ 
/var/mobile/Containers/Data/Application/<UUID>/Library/ 
/var/mobile/Containers/Data/Application/<UUID>/tmp/


## Environment setup:

apt-get install inetutils syslogd less com.autopear.installipa class-dump com.ericasadun.utilities odcctools cycript sqlite3 adv-cmds bigbosshackertools strings coreutils binutils coreutils-bin ldid debianutils busybox darwintools



## Utils:


$ plutil -convert xml1 Info.plist -o -   // outputs XML to stdout
$ plutil -convert xml1 Info.plist -o Info-xml.plist  // output to file
$ plutil -convert binary1 Info-xml.plist -o Info-bin.plist  // convert from xml to binary1

## Read the system logs:

socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock




## Binary Checks

1. $ otool -hV application  // PIE
2. $ otool -Iv application | grep stack  // Stack Canary
3. $ otool -Iv DamnVulnerableIOSApp | grep release  // ARC
4. $ otool -L application  // List the libraries used by the binary
5. $ otool -IV application  // List the symbols exported by the binary
6. $ otool -l application   // display load-commands
7. $ otool -oV application  // inspect the objective-c segment
8. $ otool -l application | grep -A 4 LC_ENCRYPT


## From FAT Binary to Thin using lipo:

lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
class-dump DVIA32



## Certificate Validation

> Example accepting self-signed certs using NSURLConnection:
```
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge: (NSURLAuthenticationChallenge *)challenge 
{ 
    if ([challenge.protectionSpace.authenticationMethod 
isEqualToString:NSURLAuthenticationMethodServerTrust]) 
    { 
        [challenge.sender useCredential:[NSURLCredential 
credentialForTrust:challenge.protectionSpace.serverTrust] 
forAuthenticationChallenge:challenge]; 
        [challenge.sender 
continueWithoutCredentialForAuthenticationChallenge:challenge]; 
        return; 
    } 
} 
```

> Example accepting self-signed certs using NSURLSession:
```
- (void)URLSession:(NSURLSession *)session 
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, 
NSURLCredential *))completionHandler 
{ 
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) 
    { 
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]; 
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential); 
    } 
} 
```

> Example disabling certificate checks using Carbon Framework:
```
NSDictionary *sslSettings = [NSDictionary dictionaryWithObjectsAndKeys: 
(id)kCFBooleanFalse, (id)kCFStreamSSLValidatesCertificateChain, nil]; 
CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, sslSettings);
```

When an application is using the Secure Transport API, you may find that the kSSLSessionOptionBreakOnServerAuth option is set on the SSL session. This disables the API’s built-in certificate validation but does not necessarily mean that the application does not implement its own custom trust evaluation routines, and therefore you should further explore the code to check for implantation of chain validation code. 

> Example disabling built-in certificate validation with Secure Transport API:
```
SSLSetSessionOption(ssl_ctx->st_ctxr, kSSLSessionOptionBreakOnServerAuth, true) 
```

If a developer needs to weaken certificate validation (for example, during development) using CFNetwork or the Secure Transport API, Apple recommends implementing a custom certificate validation routine using the Trust Services API.


## SSL Network Security

Apart from disabling checks over the certificate chain, other settings may be modified if Carbon Framework or Secure Transport API is being used.

+] For Carbon Framework:

* The kCFStreamSSLLevel key in the kCFStreamPropertySSLSettings dictionary specifies the SSL Protocol Version to use. 

+] For Secure Transport API:

* SSLSetProtocolVersion() and SSLSetProtocolVersionEnabled() functions; Any constant different than kTLSProtocol12 is wrong.
* SSLSetEnabledCiphers


## Data Storage

* Sensitive content directly stored by the application in plaintext
* Sensitive content directly stored by the application that is encrypted using a custom encryption implementation but using an insecure encryption key or in an otherwise easily reversible format
* Sensitive content directly stored by the application but not in a suitable data protection class
* Sensitive content inadvertently stored by the application by virtue of iOS

NSFileProtectionCompleteUntilFirstUserAuthentication or kSecAttrAccessibleAfterFirstUnlock are discouraged for sensitive data.


* Data Protection used over files: 
  https://github.com/ciso/ios-dataprotection
  http://www.securitylearn.net/2012/10/18/extracting-data-protection-class-from-files-on-ios/
    ./FileDP -[F/D] [FilePath/DirecotryPath]

* Data Protection Level over Keychain files: keychain_dump (run as root in the device) https://code.google.com/p/iphone-dataprotection/downloads/detail?name=keychain_dump
Try this one: https://github.com/NitinJami/keychaineditor

* Instrumentation of the iOS runtime to get the Protection-Level of files during creation: https://code.google.com/archive/p/snoop-it/


Local Data Storage Analysis:

1. Check app Data directory /private/var/mobile/Containers/Data/Application/<app
Bundle>
	a. .db - using SQLite - check with sqlite3
	b. plists
2. NSUserDefaults
	a. /User/Library/Preferences/
	b. /<app>/Library/Preferences/
3. Keychain protection class
	a. fileDP tool*
4. Application screenshots
	a. /private/var/mobile/Containers/Data/Application/<BundleID>/Library/Caches/Snapshots/
5. WebView caching
	a. /User/Library/Caches/*/Cache.db
	b. /Library/Caches/*/Cache.db
6. Forensic approach:
	a. ls -lR --full-time before application install, after install and after first use diff the results and
check any files that changed
	b. use strings on any binary/unidentified file formats
	c. check for WAL files that may contain uncommitted DB transactions


## Custom Scheme Handlers

The schemes registered by the application can be found in the info.plist file under the CFBundleURLTypes key. To understand what it does, it is necessary to reverse engineer the application:openURL delegate.



## XML Injection

iOS ships two XML parsers: NSXMLParser and libxml2. None of them are vulnerable to million laughs attack. None of them resolve external entities by default.
To enable NSXMLParser to resolve external entities the setShouldResolveExternalEntities option must be set to YES by the application.


## Data Leakage

* State Transition Leak:

When the application is suspended in the background, iOS takes a snapshot of the pp and stores it in the application's cache directory. The snapshot is a PNG image that displays the current view of the device when the state change was initiated. If that state contained sensitive information, it will be leaked through this image file.
To avoid this, developers can implement a delegate method called applicationDidEnterBackground to do the appropriate actions.

* Keyboard Caching:

Almost every non-numeric word is cached on the filesystem in plaintext in the keyboard cache file located in /var/mobile/Lirary/Keyboard

Application data such as usernames and passwords are going to be cached as well unless the fields are marked with the secureTextEntry property set to YES or the autocorrectionType property set to UITextAutocorrectionTypeNo.

* HTTP Response Caching: review the content of ~/Library/Caches/Cache.db to ensure there is sensitive content inadvertenly cached.

## Format String Vulnerabilities

NSLog

[NSString stringWithFormat]

[NSString stringByAppendingFormat]

[NSString initWithFormat]

[NSMutableString appendFormat]

[NSAlert alertWithMessageText]

[NSAlert informativeTextWithFormat]

[NSException format]

[NSMutableString appendFormat]

[NSPredicate predicateWithFormat]

NSRunAlertPanel




+] Dynamic Analysis:

Introspy: https://github.com/iSECPartners/Introspy-iOS/releases/

Installation:

wget https://github.com/iSECPartners/Introspy-iOS/releases/download/ios-tracer-v0.4/com.isecpartners.introspy-v0.4-iOS_7.deb --no-check-certificate
dpkg -i com.isecpartners.introspy-v0.4-iOS_7.deb

## Respring

killall -HUP SpringBoard   // Reload Spring!
killall -HUP backboardd

Launch Intrspy and select the application to monitor; then use the target application to generate the logs into Introspy's database.

To generate de report:

$ python ./introspy.py --outdir report mydatabase.db


## Theos Setup

export THEOS=/root/theos
git clone --recursive git://github.com/theos/theos.git $THEOS

echo "export THEOS=/root/theos" >> ~/.bashrc
echo "export PATH=$THEOS/bin:$PATH" >> ~/.bashrc

As the Substrate library does not come installed on these platforms nor bundled with Theos, copy /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate from the device to the local $THEOS/lib folder and rename it to libsubstrate.dylib. Similarly, copy /Library/Frameworks/CydiaSubstrate.framework/Headers/CydiaSubstrate.h to your local $THEOS/include folder and rename it to substrate.h.

SDK: https://sdks.website/

Take the SDK and put it in $THEOS/sdks with a folder name like iPhoneOS9.3.sdk

Run theos:

$THEOS/bin/nic.pl




+] Cydia Substrate:

To install an extension (tweak) you simply place the compiled dynamic library in the /Library/MobileSubstrate/DynamicLibraries directory for it to be loaded into an application by MobileLoader, which is the component of the Substrate framework responsible for processing extensions. To prevent your extension being loaded into every newly created process, Substrate supports filters. Filters are property list files in either binary plist, XML, or JSON format and should be named using the same convention as your tweak, with the .plist file extension. 

For example, the following directory listing shows an extension named mdsectweak.dylib with the associated filter file mdsectweak.plist:

<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
"http://www.apple.com/DTDs/PropertyList-1.0.dtd"> 
<plist version="1.0"> 
<dict> 
        <key>Filter</key> 
        <dict> 
                <key>Bundles</key> 
                <array> 
                        <string>com.mdsec.lab1-1a</string> 
                </array> 
        </dict> 
</dict> 
</plist>


+] Binary Cookie Reader: http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py



Investigate Application Extension Attacks
