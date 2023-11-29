package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.net.ssl.SSLSocket;
import utility.TLSClientBidi;
import utility.TLSServerBidi;

/**
 *
 * @author Nakamoteam
 */
public class Timer {

    private static final int[] ports = {50010, 50000, 50001, 50002};

    /**
     * @brief Timer si occupa di scandire il tempo di durata della finestra
     * temporale [T1-T2] e far stoppare tutti i server al termine
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.InterruptedException
     */
    public static void main(String[] args) throws IOException, InterruptedException, Exception {
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreTim.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sertim");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreTim.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sertim");

        // Connessione con Sgen per avviare la finestra temporale [T1-T2] delle votazioni
        TLSServerBidi timFromGen = new TLSServerBidi(50021);
        SSLSocket socket = timFromGen.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania");
        socket.close();

        System.out.println("Sleep start");
        Thread.sleep(60000);
        System.out.println("Sleep end");

        // Connessione con tutti i server necessari per inviare lo stop
        for (int i = 0; i < ports.length; i++) {
            TLSClientBidi timerToSomeone = new TLSClientBidi("localhost", ports[i], ".\\certificates\\keystoreTim.jks", "sertim");
            ObjectOutputStream out = new ObjectOutputStream(timerToSomeone.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(timerToSomeone.getcSock().getInputStream());

            out.writeUTF("stop");
            out.flush();
            if (in.readInt() == 1) {
                System.out.println("Stopping SUCCESS");
            } else {
                System.out.println("Stopping ERROR");
            }

            out.close();
            in.close();
            timerToSomeone.getcSock().close();
        }
    }
}
