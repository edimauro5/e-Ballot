package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import static java.lang.Math.abs;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.util.encoders.Hex;
import utility.Credential;
import utility.ElGamalPK;
import utility.Schnorr;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;
import utility.VotesDB;

/**
 *
 * @author Nakamoteam
 */
public class Splat {

    private static final int[] ports = {50000, 50001, 50002};

    private static final HashMap<String, Integer> databaseMI;

    static {
        databaseMI = new HashMap<>();
        databaseMI.put("EMDM00V001", 0);
        databaseMI.put("ACXX99V002", 0);
        databaseMI.put("ADGX99V003", 0);
        databaseMI.put("SGXX99V004", 0);
    }

    /**
     * @return Codice fiscale del Voter o null
     * @brief Metodo che permette di verificare la correttezza del certificato
     * digitale
     * @param session Sessione della connessione
     * @throws javax.net.ssl.SSLPeerUnverifiedException
     */
    public static String cdVerify(SSLSession session) throws SSLPeerUnverifiedException {
        // getPeerPrincipal returns info about the X500Principal of the other peer
        X500Principal id = (X500Principal) session.getPeerPrincipal();
        // X500Principal is the field that contains CF, Common Name and Country

        String[] strings = id.getName().split(",");
        String CF = null;

        if (strings[0].startsWith("1.3.18.0.2.6.73")) {
            CF = new String(Hex.decode(strings[0].substring(21)));
        }

        if (databaseMI.containsKey(CF)) {
            if (databaseMI.get(CF) == 0) {
                System.out.println("CD admitted SUCCESS");
            } else {
                System.out.println("Credential already emitted ERROR");
            }
        } else {
            System.out.println("Voter not admitted ERROR");
        }

        if (databaseMI.containsKey(CF) && databaseMI.get(CF) == 0) {
            return CF;
        }
        return null;
    }

    /**
     * @brief Metodo che permette di inviare il voto a Sbal
     * @param ID ID univoco del Voter
     * @param oldSV voto già presente nel database espresso dal Voter
     * @param newSV nuovo voto espresso dal Voter
     * @throws java.io.IOException
     */
    public static Boolean sendToBal(String ID, SignedVote oldSV, SignedVote newSV) throws IOException, Exception {
        if (oldSV.getVoteCT() == null && oldSV.getSign() == null && newSV.getVoteCT() == null && newSV.getSign() == null) {
            return false;
        }

        int bal = abs(ID.hashCode() % ports.length);

        System.out.println("bal: " + bal);
        System.out.println("port: " + ports[bal]);

        TLSClientBidi platToBal = new TLSClientBidi("localhost", ports[bal], ".\\certificates\\keystorePlat.jks", "serplat");
        ObjectOutputStream out = new ObjectOutputStream(platToBal.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(platToBal.getcSock().getInputStream());

        out.writeUTF("voting");
        out.flush();

        if (in.readInt() != 1) {
            System.out.println("Sending string voting ERROR");
        }
        System.out.println("Sending string voting SUCCESS");
        out.writeObject(newSV);
        out.flush();
        if (in.readBoolean() == false) {
            System.out.println("Digital signature of vote check ERROR");
            out.close();
            in.close();
            platToBal.getcSock().close();
            return false;
        }
        if (oldSV.getVoteCT() != null && oldSV.getSign() != null) {
            out.writeUTF("two messages");
            out.flush();

            out.writeObject(oldSV);
            out.flush();

            if (in.readBoolean() == false) {
                System.out.println("Digital signature of vote check ERROR");
                out.close();
                in.close();
                platToBal.getcSock().close();
                return false;
            }
        }

        out.writeUTF("one message");
        out.flush();

        if (in.readBoolean() == false) {
            System.out.println("Vote not added in Sbal " + bal + "ERROR");
            out.close();
            in.close();
            platToBal.getcSock().close();
            return false;
        }

        System.out.println("Vote added in Sbal " + bal + " SUCCESS");
        return true;
    }

    /**
     * @brief Splat si occupa di far registrare e di far votare i Voters e di
     * inviare i voti ai Sbal
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, Exception {
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystorePlat.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "serplat");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststorePlat.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "serplat");

        // Connessione con Sgen per ricevere la PK
        TLSServerBidi platFromSomeone = new TLSServerBidi(50010);
        SSLSocket socket = platFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        ElGamalPK PK = (ElGamalPK) in.readObject();
        out.writeInt(1);
        out.flush();
        System.out.println("Arriving PK SUCCESS");

        out.close();
        in.close();
        socket.close();

        // Connessione con Voter per ottenere credenziali
        VotesDB platDB = new VotesDB();

        OUTER:
        while (true) {
            socket = platFromSomeone.accept();
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            String request = in.readUTF();
            if (null != request) {
                switch (request) {
                    case "registration":
                        System.out.println("I received a request for an ID");
                        String CF = cdVerify(socket.getSession());
                        if (CF == null) {
                            System.out.println("CD check ERROR");
                            out.writeBoolean(false);
                            out.flush();
                            out.close();
                            in.close();
                            socket.close();
                        } else {
                            System.out.println("CD check SUCCESS");
                            out.writeBoolean(true);
                            out.flush();
                            String ID = null;

                            do {
                                ID = Utils.generateID();
                            } while (platDB.getVotesDB().containsKey(ID));

                            out.writeUTF(ID);
                            out.flush();

                            if (in.readInt() == 1) {
                                System.out.println("Sending ID SUCCESS");

                                Credential cred = (Credential) in.readObject();

                                if (!ID.equals(cred.getID())) {
                                    System.out.println("Credential check ERROR");
                                    out.writeBoolean(false);
                                    out.flush();
                                    out.close();
                                    in.close();
                                    socket.close();
                                } else {
                                    System.out.println("Credential check SUCCESS");
                                    out.writeBoolean(true);
                                    out.flush();

                                    if (platDB.addCredential(cred) == false) {
                                        System.out.println("Adding credential ERROR");
                                        out.writeBoolean(false);
                                        out.flush();
                                        out.close();
                                        in.close();
                                        socket.close();
                                    } else {
                                        System.out.println("Adding credential SUCCESS");
                                        out.writeBoolean(true);
                                        out.flush();
                                        databaseMI.put(CF, 1); //assumiamo funzioni sempre
                                    }
                                }
                            } else {
                                System.out.println("Sending ID ERROR");
                                out.close();
                                in.close();
                                socket.close();
                            }
                        }
                        break;
                    case "voting":
                        Credential cred = (Credential) in.readObject();
                        if (platDB.checkCredential(cred) == false) {
                            System.out.println("Credential check ERROR");
                            out.writeBoolean(false);
                            out.flush();
                            out.close();
                            in.close();
                            socket.close();
                        } else {
                            System.out.println("Credential check SUCCESS");
                            out.writeBoolean(true);
                            out.flush();

                            out.writeObject(PK);
                            out.flush();
                            if (in.readInt() == 1) {
                                System.out.println("Sending PK SUCCESS");

                                SignedVote sv = (SignedVote) in.readObject();
                                SignedVote oldSV = null;

                                if (sv.getVoteCT() != null && sv.getSign() != null) {
                                    if (!Schnorr.verify(sv.getSign(), sv.getSignedPK(), Utils.toString(Utils.objToByteArray(sv.getVoteCT())))) {
                                        System.out.println("Digital signature of vote check ERROR");
                                        out.writeBoolean(false);
                                        out.flush();
                                        out.close();
                                        in.close();
                                        socket.close();
                                    } else {
                                        System.out.println("Digital signature of vote check SUCCESS");

                                        oldSV = platDB.getSignedVote(cred.getID(), sv.getSignedPK());
                                        if (sendToBal(cred.getID(), oldSV, sv)) {
                                            platDB.setSignedVote(cred.getID(), sv);
                                            System.out.println("Adding vote SUCCESS");
                                            out.writeBoolean(true);
                                            out.flush();
                                        } else {
                                            System.out.println("Adding vote ERROR");
                                            out.writeBoolean(false);
                                            out.flush();
                                        }
                                    }
                                } else {
                                    oldSV = platDB.getSignedVote(cred.getID(), sv.getSignedPK());
                                    if (sendToBal(cred.getID(), oldSV, sv)) {
                                        platDB.setSignedVote(cred.getID(), sv);
                                        System.out.println("Adding vote SUCCESS");
                                        out.writeBoolean(true);
                                        out.flush();
                                    } else {
                                        System.out.println("Adding vote ERROR");
                                        out.writeBoolean(false);
                                        out.flush();
                                    }
                                }
                            } else {
                                System.out.println("Sending PK ERROR");
                            }
                        }
                        break;
                    case "stop":
                        out.writeInt(1);
                        out.flush();
                        System.out.println("e-ballot ended");
                        out.close();
                        in.close();
                        socket.close();
                        break OUTER;
                    default:
                        System.out.println("Request not accepted ERROR");
                }
            }
        }
    }

}
