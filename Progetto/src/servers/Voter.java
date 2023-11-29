package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import utility.Credential;
import utility.ElGamalCT;
import utility.ElGamalEnc;
import utility.ElGamalPK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Voter {

    /**
     * @brief Metodo che permette di ottenere un ID personale dopo aver
     * verificato la correttezza del certificato digitale
     * @param socket Socket su cui è stata avviata la connessione
     * @param out Stream di output della connessione
     * @param in Stream di input della connessione
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    private static String sendCDForID(SSLSocket socket, ObjectOutputStream out, ObjectInputStream in) throws IOException, ClassNotFoundException, Exception {
        System.out.println("I want an ID");
        out.writeUTF("registration");
        out.flush();
        if (in.readBoolean() == false) {
            System.out.println("CD check ERROR");
            return null;
        }

        String ID = in.readUTF();
        System.out.println("Arriving ID SUCCESS");
        out.writeInt(1);
        out.flush();

        return ID;
    }

    /**
     * @brief Metodo che permette di associare all'ID una Password
     * @param ID ID univoco del Voter
     * @param pwd Password scelta dal Voter e che viene associata all'ID
     * @param socket Socket su cui è stata avviata la connessione
     * @param out Stream di output della connessione
     * @param in Stream di input della connessione
     * @throws java.io.IOException
     */
    private static Credential sendCredential(String ID, String pwd, SSLSocket socket, ObjectOutputStream out, ObjectInputStream in) throws IOException, Exception {
        if ("".equals(pwd)) {
            System.out.println("Password empty ERROR");
            return null;
        }

        Credential cred = new Credential(ID, pwd);
        out.writeObject(cred);
        out.flush();

        if (in.readBoolean() == false) {
            System.out.println("Credential check ERROR");
            return null;
        }

        if (in.readBoolean() == false) {
            System.out.println("Credential not added ERROR");
            return null;
        }

        return cred;
    }

    /**
     * @brief Metodo che permette di votare
     * @param cred ID e Password del Voter
     * @param vote Preferenza espressa dal Voter
     * @param numVoter numero del Voter (necessario per l'esecuzione)
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    private static boolean vote(Credential cred, String vote, int numVoter) throws IOException, ClassNotFoundException, Exception {
        if (!"0".equals(vote) && !"1".equals(vote) && !"-1".equals(vote) && !"null".equals(vote)) {
            System.out.println("Vote incorrect ERROR");
            return false;
        }

        TLSClientBidi votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter" + numVoter + ".jks", "voter" + numVoter);
        ObjectOutputStream out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        System.out.println("I want to vote");
        out.writeUTF("voting");
        out.flush();

        out.writeObject(cred);
        out.flush();

        if (in.readBoolean() == false) {
            System.out.println("Credential check ERROR");
            out.close();
            in.close();
            votToPlat.getcSock().close();
            return false;
        }

        ElGamalEnc PKEnc = new ElGamalEnc((ElGamalPK) in.readObject());
        out.writeInt(1);
        out.flush();
        Schnorr signer = new Schnorr(512);

        ElGamalCT voteCT = null;
        SchnorrSig sign = null;
        if (!"null".equals(vote)) {
            voteCT = PKEnc.encryptInTheExponent(BigInteger.valueOf(Integer.parseInt(vote)));
            sign = signer.sign(Utils.toString(Utils.objToByteArray(voteCT)));
        }

        out.writeObject(new SignedVote(voteCT, sign, signer.getPK()));
        out.flush();

        if (in.readBoolean() == false) {
            if (voteCT == null && sign == null) {
                System.out.println("No previous vote ERROR");
            } else {
                System.out.println("Digital signature of vote check ERROR");
            }
            System.out.println("Vote ERROR");
            out.close();
            in.close();
            votToPlat.getcSock().close();
            return false;
        }
        System.out.println("Vote SUCCESS");

        out.close();
        in.close();
        votToPlat.getcSock().close();

        return true;
    }

    /**
     * @brief Voter consiste nell'insieme dei votanti e delle loro azioni
     * @param args the command line arguments
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws ClassNotFoundException, Exception {
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreVoters.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "voters");

        // Voter 1 vota e modifica
        TLSClientBidi votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter1.jks", "voter1");
        ObjectOutputStream out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID1 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred1 = null;
        if (ID1 != null) {
            String pwd1 = "pwdv1";
            cred1 = sendCredential(ID1, pwd1, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred1 != null) {
            vote(cred1, "-1", 1);
            vote(cred1, "1", 1);
        }

        // Voter 2 usa ID di Voter 1 poi il suo e vota
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter2.jks", "voter2");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID2 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred2 = null;
        if (ID2 != null) {
            String pwd2 = "pwdv2";
            cred2 = sendCredential(ID1, pwd2, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter2.jks", "voter2");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        ID2 = sendCDForID(votToPlat.getcSock(), out, in);
        cred2 = null;
        if (ID2 != null) {
            String pwd2 = "pwdv2";
            cred2 = sendCredential(ID2, pwd2, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred2 != null) {
            vote(cred2, "1", 2);
        }

        // Voter 3 vota a nome di Voter 1 poi vota a nome suo e annulla il suo voto
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter3.jks", "voter3");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID3 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred3 = null;
        if (ID3 != null) {
            String pwd3 = "pwdv3";
            cred3 = sendCredential(ID3, pwd3, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred3 != null) {
            vote(cred3, "0", 3);
            vote(cred3, "null", 3);
            vote(cred3, "-1", 3);
        }

        // Voter 4 vota annulla senza aver mai votato
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter4.jks", "voter4");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID4 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred4 = null;
        if (ID4 != null) {
            String pwd4 = "pwdv4";
            cred4 = sendCredential(ID4, pwd4, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred4 != null) {
            vote(cred4, "null", 4);
        }

        // Voter 5 tenta di accedere, ma non ha i requisiti richiesti
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter5.jks", "voter5");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID5 = sendCDForID(votToPlat.getcSock(), out, in);

        out.close();
        in.close();
        votToPlat.getcSock().close();

        // Voter 1 tenta di ottenere nuove credenziali
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter1.jks", "voter1");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        ID1 = sendCDForID(votToPlat.getcSock(), out, in);

        out.close();
        in.close();
        votToPlat.getcSock().close();
    }

}
