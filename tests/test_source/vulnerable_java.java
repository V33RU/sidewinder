/*
 * Intentionally vulnerable Java code for scanner validation.
 * DO NOT use in production.
 */
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WifiScanner {
    private static final Logger logger = LogManager.getLogger();

    /* wifi_jndi: SSID logged via Log4j (pre-patch) */
    public void logDiscoveredAP(String ssid) {
        logger.info("Detected AP: " + ssid);
    }

    /* wifi_jndi: Log4j warn with SSID */
    public void warnRogueAP(String ssid) {
        logger.warn("Rogue AP detected: " + ssid);
    }
}
