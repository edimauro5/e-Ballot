package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.SchnorrSig;
import utility.TLSServerBidi;

/**
 *
 * @author Nakamoteam
 */
public class Stab {

    private static final int[] ports = {50000, 50001, 50002};

    /**
     * @brief Stab si occupa di fare un merge tra tutti i database locali dei
     * Sbal e mostrarne il contenuto al termine dell'e-ballot
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreTab.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sertab");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreTab.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sertab");

        HashMap<ElGamalCT, SchnorrSig> listVotes = new HashMap<>();

        TLSServerBidi tabFromBal = new TLSServerBidi(50020);

        for (int i = 0; i < ports.length; i++) {
            SSLSocket socket = tabFromBal.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania");
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            listVotes.putAll((HashMap<ElGamalCT, SchnorrSig>) in.readObject());
            out.writeInt(1);
            out.flush();
        }

        System.out.println("Table publication:\n");
        for (ElGamalCT key : listVotes.keySet()) {
            System.out.println(key + "\t" + listVotes.get(key));
        }
    }

}
