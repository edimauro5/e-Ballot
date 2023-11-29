package utility;

import java.io.Serializable;

/**
 *
 * @author Nakamoteam
 */
public class SignedVote implements Serializable {

    private final ElGamalCT voteCT;
    private final SchnorrSig sign;
    private final SchnorrPK signedPK;

    public SignedVote(ElGamalCT voteCT, SchnorrSig sign, SchnorrPK signedPK) {
        this.voteCT = voteCT;
        this.sign = sign;
        this.signedPK = signedPK;
    }

    public ElGamalCT getVoteCT() {
        return voteCT;
    }

    public SchnorrSig getSign() {
        return sign;
    }

    public SchnorrPK getSignedPK() {
        return signedPK;
    }
}
