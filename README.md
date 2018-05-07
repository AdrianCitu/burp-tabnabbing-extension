# burp-tabnabbing-extension
This is a Burp Suite Pro extension that is able to find the “Reverse Tabnabbing” attack.
For more information about “Reverse Tabnabbing” attack please see https://www.owasp.org/index.php/Reverse_Tabnabbing

By defaut the extension will scan the pages entirely but this behavior can be customized using the
"tabnabbing.pagescan.strategy" (java) system variables.
The possible options of "tabnabbing.pagescan.strategy" are:
 * STOP_AFTER_FIRST_FINDING (stops the scan after first finding).
 * STOP_AFTER_FIRST_HTML_AND_JS_FINDING (stop the scan after first HTML and JavaScript finding).
 * SCAN_ENTIRE_PAGE (default value).
     
The "tabnabbing.pagescan.strategy" system variable can be set-up at start time like this:

java -Dtabnabbing.pagescan.strategy=SCAN_ENTIRE_PAGE -jar burpsuite-pro-x.x.xx.jar
 
 
 Requirements to run the extension:
  * Java 8 or later.
  * Burp Suite Professional version 1.7.33 (or later ?) - not sure that the next API
    versions will be backward compatible.
 
Some code metrics (from sonarcloud): https://sonarcloud.io/dashboard?id=com.github.adriancitu.burp%3Atabnabbing
If you want to know more technical details about how the plug-in was done: https://adriancitu.com/2018/05/07/tabnabbing-burp-extension/ 
