package burp;

import com.github.adriancitu.burp.tabnabbing.scanner.ScannerCheck;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(
            final IBurpExtenderCallbacks iBurpExtenderCallbacks) {

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("(Reverse) Tabnabbing checks.");

        // register the custom scanner check
        callbacks.registerScannerCheck(new ScannerCheck(helpers));
    }
}
