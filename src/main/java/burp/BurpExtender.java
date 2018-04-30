package burp;

import com.github.adriancitu.burp.tabnabbing.scanner.ScannerCheck;

public class BurpExtender implements IBurpExtender {


    @Override
    public void registerExtenderCallbacks(
            final IBurpExtenderCallbacks iBurpExtenderCallbacks) {


        // set our extension name
        iBurpExtenderCallbacks.setExtensionName("(Reverse) Tabnabbing checks.");

        // register the custom scanner
        iBurpExtenderCallbacks.registerScannerCheck(
                new ScannerCheck(iBurpExtenderCallbacks.getHelpers()));
    }
}
