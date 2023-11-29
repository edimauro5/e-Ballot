package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedShare;
import utility.TLSClientBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Sgen {

    private static final int[] ports = {50000, 50001, 50002, 50010};

    /**
     * @brief Sgen si occupa di generare le shares di SK da distribuire ai Sbal
     * per permettere la Threashold El Gamal Decryption, la PK necessaria per
     * permettere ai Voters di votare e di avviare il Timer subito prima di
     * terminare
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreGen.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sergen");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreGen.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sergen");

        ElGamalGen gen = new ElGamalGen(512);

        ElGamalPK[] arrPK = new ElGamalPK[ports.length - 1];
        Schnorr signer = new Schnorr(512);

        // Connessione con tutti i Sbal per inviare le shares
        for (int i = 0; i < ports.length - 1; i++) {
            TLSClientBidi genToBal = new TLSClientBidi("localhost", ports[i]);

            ObjectOutputStream out = new ObjectOutputStream(genToBal.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(genToBal.getcSock().getInputStream());

            ElGamalSK shareSK = gen.getPartialSecret();

            SchnorrSig sign = signer.sign(Utils.toString(Utils.objToByteArray(shareSK)));

            out.writeObject(new SignedShare(shareSK, sign, signer.getPK()));
            out.flush();

            if (in.readBoolean() == false) {
                System.out.println("Digital signature of share check ERROR");
                out.close();
                in.close();
                genToBal.getcSock().close();
                return;
            }

            if (!shareSK.getPK().equals(in.readObject())) {
                System.out.println("PK check ERROR");
                out.writeBoolean(false);
                out.flush();
                out.close();
                in.close();
                genToBal.getcSock().close();
                return;
            }
            out.writeBoolean(true);
            out.flush();
            arrPK[i] = shareSK.getPK();

            out.close();
            in.close();
            genToBal.getcSock().close();
        }

        // Connessione con tutti i server necessari per inviare la PK
        ElGamalPK PK = gen.aggregatePartialPublicKeys(arrPK);

        for (int i = 0; i < ports.length; i++) {
            TLSClientBidi genToSomeone = new TLSClientBidi("localhost", ports[i]);

            ObjectOutputStream out = new ObjectOutputStream(genToSomeone.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(genToSomeone.getcSock().getInputStream());

            out.writeObject(PK);
            out.flush();

            if (in.readInt() == 1) {
                System.out.println("Sending Key SUCCESS");
            } else {
                System.out.println("Sending Key ERROR");
            }

            out.close();
            in.close();
            genToSomeone.getcSock().close();
        }
        TLSClientBidi genToTimer = new TLSClientBidi("localhost", 50021);
        genToTimer.getcSock().close();

    }

}
