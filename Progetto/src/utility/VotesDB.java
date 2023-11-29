package utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 *
 * @author Nakamoteam
 */
public class VotesDB {

    private class ValueDB {

        private final String hashedPwd;
        private final String salt;
        private ElGamalCT voteCT;
        private SchnorrSig sign;

        public ValueDB(String hashedPwd, String salt) {
            this.hashedPwd = hashedPwd;
            this.salt = salt;
            this.voteCT = null;
            this.sign = null;
        }
    }

    private HashMap<String, ValueDB> votesDB;

    public VotesDB() {
        votesDB = new HashMap<>();
    }

    public HashMap<String, ValueDB> getVotesDB() {
        return votesDB;
    }

    public ValueDB getValueDB(String ID) {
        return votesDB.get(ID);
    }

    public boolean addCredential(Credential cred) throws NoSuchAlgorithmException {
        if (votesDB.containsKey(cred.getID())) {
            return false;
        }

        SecureRandom sc = new SecureRandom();
        byte[] salt = new byte[16];
        sc.nextBytes(salt);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] hashedPwd = md.digest(Utils.toByteArray(cred.getPwd()));

        votesDB.put(cred.getID(), new ValueDB(Utils.toString(hashedPwd), Utils.toString(salt)));

        return true;
    }

    public boolean checkCredential(Credential cred) throws NoSuchAlgorithmException {
        ValueDB value = votesDB.get(cred.getID());

        if (value == null) {
            return false;
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Utils.toByteArray(value.salt));
        byte[] hashedPwd = md.digest(Utils.toByteArray(cred.getPwd()));

        return value.hashedPwd.equals(Utils.toString(hashedPwd));
    }

    public SignedVote getSignedVote(String ID, SchnorrPK signedPK) {
        ValueDB value = votesDB.get(ID);

        ElGamalCT voteCT = value.voteCT;
        SchnorrSig sign = value.sign;

        return new SignedVote(voteCT, sign, signedPK);
    }

    public void setSignedVote(String ID, SignedVote sv) {
        ValueDB value = votesDB.get(ID);

        value.voteCT = sv.getVoteCT();
        value.sign = sv.getSign();
    }
}
