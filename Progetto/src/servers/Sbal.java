package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedShare;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Sbal {

    private static final int[] ports = {50000, 50001, 50002};

    /**
     * @brief Metodo che permette di far eseguire tutto ciò che deve fare uno
     * Sbal
     * @param port Numero della porta dello Sbal
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     * @throws java.net.ConnectException
     */
    private static void activateSbal(int port) throws IOException, ClassNotFoundException, Exception, ConnectException {
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreBal.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "serbal");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreBal.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "serbal");
        TLSServerBidi balFromSomeone = new TLSServerBidi(port);

        // Connessione con Sgen per ricevere la share
        SSLSocket socket = balFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania");
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        SignedShare share = (SignedShare) in.readObject();

        if (!Schnorr.verify(share.getSign(), share.getSignedPK(), Utils.toString(Utils.objToByteArray(share.getShareSK())))) {
            System.out.println("Digital signature of share check ERROR");
            System.out.println("--------------------          " + port);
            out.writeBoolean(false);
            out.flush();
            out.close();
            in.close();
            socket.close();
            return;
        }
        out.writeBoolean(true);
        out.flush();
        System.out.println("Arriving share SUCCESS");
        System.out.println("--------------------          " + port);

        ElGamalDec shareDec = new ElGamalDec((ElGamalSK) share.getShareSK());

        out.writeObject(shareDec.getPK());
        out.flush();

        if (in.readBoolean() == false) {
            System.out.println("PK check ERROR");
            System.out.println("--------------------          " + port);
            out.close();
            in.close();
            socket.close();
            return;
        }

        out.close();
        in.close();
        socket.close();

        // Connessione con Sgen per ricevere la PK
        socket = balFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        ElGamalPK PK = (ElGamalPK) in.readObject();
        if (PK != null) {
            out.writeInt(1);
            out.flush();
            System.out.println("Arriving PK SUCCESS");
            System.out.println("--------------------          " + port);
        } else {
            out.writeInt(0);
            out.flush();
            System.out.println("Arriving PK ERROR");
            System.out.println("--------------------          " + port);

        }

        out.close();
        in.close();
        socket.close();

        // Connessione con Splat per ricevere i voti (inizio dell'e-ballot)
        System.out.println("\nI am ready to start the e-ballot\n");
        System.out.println("--------------------          " + port);

        HashMap<ElGamalCT, SchnorrSig> listVotes = new HashMap<>();

        OUTER:
        while (true) {
            System.out.println("sono sbal e sono entrato nel while");
            System.out.println("--------------------          " + port);

            socket = balFromSomeone.accept();
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            String request = in.readUTF();
            out.writeInt(1);
            out.flush();
            if (null != request) {
                System.out.println("request is not null and it is: " + request);
                System.out.println("--------------------          " + port);
                switch (request) {
                    case "stop":
                        out.writeInt(1);
                        //out.flush();
                        out.close();
                        in.close();
                        socket.close();
                        break OUTER;
                    case "voting":
                        SignedVote sv = (SignedVote) in.readObject();
                        out.writeBoolean(true);
                        out.flush();
                        if (sv.getVoteCT() == null && sv.getSign() == null) {
                            if ("two messages".equals(in.readUTF())) {
                                SignedVote oldSV = (SignedVote) in.readObject();

                                out.writeBoolean(true);
                                out.flush();
                                System.out.println("Arriving vote SUCCESS");
                                System.out.println("--------------------          " + port);
                                for (ElGamalCT key : listVotes.keySet()) {
                                    if (key.equals(oldSV.getVoteCT())) {
                                        if (listVotes.remove(key, listVotes.get(key))) {
                                            out.writeBoolean(true);
                                            out.flush();
                                            System.out.println("Adding vote SUCCESS");
                                            System.out.println("--------------------          " + port);
                                        } else {
                                            out.writeBoolean(false);
                                            out.flush();
                                            System.out.println("Adding vote ERROR");
                                            System.out.println("--------------------          " + port);
                                        }
                                    }
                                }
                            }
                        } else {
                            if (!Schnorr.verify(sv.getSign(), sv.getSignedPK(), Utils.toString(Utils.objToByteArray(sv.getVoteCT())))) {
                                System.out.println("Digital signature of vote check ERROR");
                                System.out.println("--------------------          " + port);
                                out.writeBoolean(false);
                                out.flush();
                            } else {
                                out.writeBoolean(true);
                                out.flush();
                                System.out.println("Arriving vote SUCCESS");
                                System.out.println("--------------------          " + port);

                                if ("two messages".equals(in.readUTF())) {
                                    SignedVote oldSV = (SignedVote) in.readObject();

                                    out.writeBoolean(true);
                                    out.flush();
                                    System.out.println("Arriving vote SUCCESS");
                                    System.out.println("--------------------          " + port);
                                    for (ElGamalCT key : listVotes.keySet()) {
                                        if (key.equals(oldSV.getVoteCT())) {
                                            if (listVotes.remove(key, listVotes.get(key)) && sv.getVoteCT() != null && sv.getSign() != null && !listVotes.containsKey(sv.getVoteCT())) {
                                                listVotes.put(sv.getVoteCT(), sv.getSign());
                                                out.writeBoolean(true);
                                                out.flush();
                                                System.out.println("Adding vote SUCCESS");
                                                System.out.println("--------------------          " + port);
                                            } else {
                                                out.writeBoolean(false);
                                                out.flush();
                                                System.out.println("Adding vote ERROR");
                                                System.out.println("--------------------          " + port);
                                            }
                                        }
                                    }
                                } else {
                                    if (sv.getVoteCT() != null && sv.getSign() != null && !listVotes.containsKey(sv.getVoteCT())) {
                                        listVotes.put(sv.getVoteCT(), sv.getSign());
                                        out.writeBoolean(true);
                                        out.flush();
                                        System.out.println("Adding vote SUCCESS");
                                        System.out.println("--------------------          " + port);
                                    } else {
                                        out.writeBoolean(false);
                                        out.flush();
                                        System.out.println("Adding vote ERROR");
                                        System.out.println("--------------------          " + port);
                                    }
                                }
                            }
                        }
                        out.close();
                        in.close();
                        socket.close();
                        break;
                    default:
                        System.out.println("Request not accepted ERROR");
                }
            }
        }
        System.out.println("\ne-ballot ended\n");
        System.out.println("--------------------          " + port);

        // Calcolo del ciphertext locale (fine dell'e-ballot)
        ElGamalCT localCT = null;
        int flag = 0;

        for (ElGamalCT key : listVotes.keySet()) {
            if (flag == 0) {
                localCT = key;
                flag = 1;
            } else {
                localCT = ElGamalCT.Homomorphism(PK, localCT, key);
            }
        }

        // Connessione con gli altri Sbal per inviare il ciphertext locale
        ArrayList<ElGamalCT> arrCT = new ArrayList<>();
        ElGamalCT tmp = null;

        for (int i = 0; i < ports.length; i++) {
            if (ports[i] != port) {
                TLSClientBidi balToBal = new TLSClientBidi("localhost", ports[i]);
                out = new ObjectOutputStream(balToBal.getcSock().getOutputStream());
                in = new ObjectInputStream(balToBal.getcSock().getInputStream());

                out.writeObject(localCT);
                out.flush();

                if (in.readInt() == 1) {
                    System.out.println("Sending local ciphertext SUCCESS");
                    System.out.println("--------------------          " + port);
                } else {
                    System.out.println("Sending local ciphertext ERROR");
                    System.out.println("--------------------          " + port);
                }

                out.close();
                in.close();
                balToBal.getcSock().close();
            } else {
                for (int j = 0; j < ports.length - 1; j++) {
                    socket = balFromSomeone.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania");
                    out = new ObjectOutputStream(socket.getOutputStream());
                    in = new ObjectInputStream(socket.getInputStream());

                    tmp = (ElGamalCT) in.readObject();

                    out.writeInt(1);
                    out.flush();
                    System.out.println("Arriving local ciphertext SUCCESS");
                    System.out.println("--------------------          " + port);

                    if (tmp != null) {
                        arrCT.add(tmp);
                    }

                    out.close();
                    in.close();
                    socket.close();
                }
            }
        }

        // Calcolo del ciphertext finale (fine dell'e-ballot)
        if (localCT == null & arrCT.isEmpty()) {
            System.out.println("Nobody voted final ciphertext is null");
            System.out.println("--------------------          " + port);
            return;
        }

        ElGamalCT finalCT = localCT;

        if (localCT == null) {
            finalCT = arrCT.get(0);
            for (int i = 1; i < arrCT.size(); i++) {
                finalCT = ElGamalCT.Homomorphism(PK, finalCT, arrCT.get(i));
            }
        } else {
            for (int i = 0; i < arrCT.size(); i++) {
                finalCT = ElGamalCT.Homomorphism(PK, finalCT, arrCT.get(i));
            }
        }

        // Connessione con gli altri Sbal per inviare ufin^(p(i))
        ElGamalCT personalDecCT = shareDec.partialDecrypt(finalCT);

        for (int i = 0; i < ports.length - 1; i++) {
            if (ports[i] != port) {
                socket = balFromSomeone.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania");
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                if (i != ports.length - 2) {
                    personalDecCT = shareDec.partialDecrypt((ElGamalCT) in.readObject());
                } else {
                    personalDecCT = (ElGamalCT) in.readObject();
                }

                out.writeInt(1);
                out.flush();
                System.out.println("Arriving partial decrypt SUCCESS");
                System.out.println("--------------------          " + port);

                out.close();
                in.close();
                socket.close();
            } else {
                for (int j = 0; j < ports.length; j++) {
                    if (ports[j] != port) {
                        TLSClientBidi balToBal = new TLSClientBidi("localhost", ports[j]);
                        out = new ObjectOutputStream(balToBal.getcSock().getOutputStream());
                        in = new ObjectInputStream(balToBal.getcSock().getInputStream());

                        out.writeObject(personalDecCT);
                        out.flush();

                        if (in.readInt() == 1) {
                            System.out.println("Sending partial decrypt SUCCESS");
                            System.out.println("--------------------          " + port);
                        } else {
                            System.out.println("Sending partial decrypt ERROR");
                            System.out.println("--------------------          " + port);
                        }

                        out.close();
                        in.close();
                        balToBal.getcSock().close();
                    }
                }
            }
        }

        // Calcolo del risultato finale dell'e-ballot
        if (port == ports[ports.length - 1]) {
            BigInteger res = shareDec.decryptInTheExponent(personalDecCT);
            System.out.println("The e-ballot result is: " + res);
            System.out.println("--------------------          " + port);
        }

        //Connessione con la bacheca per la stampa dei voti
        TLSClientBidi balToTab = new TLSClientBidi("localhost", 50020);
        out = new ObjectOutputStream(balToTab.getcSock().getOutputStream());
        in = new ObjectInputStream(balToTab.getcSock().getInputStream());

        out.writeObject(listVotes);
        out.flush();

        if (in.readInt() == 1) {
            System.out.println("Sending DB SUCCESS");
            System.out.println("--------------------          " + port);
        } else {
            System.out.println("Sending DB ERROR");
            System.out.println("--------------------          " + port);
        }

        out.close();
        in.close();
        balToTab.getcSock().close();
    }

    /**
     * @brief Sbal si occupa di ricevere i voti ed inserirli correttamente nel
     * database, di ottenere il risultato finale del ballottaggio collaborando
     * con gli altri Sbal e di inviare il database a Stab
     * @param args the command line arguments
     * @throws java.lang.InterruptedException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws InterruptedException, ClassNotFoundException, Exception {
        List<Callable<Void>> taskList = new ArrayList<>();
        for (int i = 0; i < ports.length; i++) {
            int port = ports[i];
            Callable<Void> callable = new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    activateSbal(port);
                    return null;
                }
            };
            taskList.add(callable);
        }
        ExecutorService executor = Executors.newFixedThreadPool(3);
        executor.invokeAll(taskList);
        executor.shutdown();
        /*
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int numPort = scan.nextInt();
        activateSbal(numPort);
         */
    }

}
