package utility;

import java.io.Serializable;

/**
 *
 * @author Nakamoteam
 */
public class Credential implements Serializable {

    private final String ID;
    private final String pwd;

    public Credential(String ID, String pwd) {
        this.ID = ID;
        this.pwd = pwd;
    }

    public String getID() {
        return ID;
    }

    public String getPwd() {
        return pwd;
    }
}
