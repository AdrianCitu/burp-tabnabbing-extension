package burp;

import com.github.adriancitu.burp.tabnabbing.scanner.ScannerCheck;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(
            final IBurpExtenderCallbacks iBurpExtenderCallbacks) {


        // set our extension name
        iBurpExtenderCallbacks.setExtensionName("(Reverse) Tabnabbing checks.");

        // register the custom scanner check
        iBurpExtenderCallbacks.registerScannerCheck(
                new ScannerCheck(iBurpExtenderCallbacks.getHelpers()));
    }
}
