package burp;

import com.github.adriancitu.burp.tabnabbing.scanner.ScannerCheck;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(
            final IBurpExtenderCallbacks iBurpExtenderCallbacks) {


        // set our extension name
        callbacks.setExtensionName("(Reverse) Tabnabbing checks.");

        // register the custom scanner check
        callbacks.registerScannerCheck(new ScannerCheck(callbacks.getHelpers()));
    }
}
