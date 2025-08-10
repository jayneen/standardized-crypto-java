import java.math.BigInteger;
import java.security.SecureRandom;

public class Scnhorr
{
    //Probably the whole thing
    public void generateKeypair(byte[] theMessage, Edwards theCurve, String thePassphrase)
    {
        //I think I'll use this later
        BigInteger r = theCurve.r;
        Edwards.Point G = theCurve.gen();

        //Find private key, s, from passphrase
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.absorb(passphrase.getBytes());
        byte[] sBytes = shake.squeeze(32);
        BigInteger s = new BigInteger(1, sBytes).mod(r);
        //TODO
        //This might need to be modulo or something im not sure yet
        Edwards.Point V = G*s;

        //Ensure x-coordinate LSB of public key is 0
        if (V.x.testBit(0))
        {
            s = r.subtract(s);
            V = V.negate();
        }

        //Generate a random nonce, k
        SecureRandom rngesus = new SecureRandom();
        int rbytes = (E.r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.r);
        //TODO
        //may need to modulo here too
        Edwards.Point U = G*k;

        //Compute h = H(Uy || theMessage)
        byte[] Uy = U.y.toByteArray();
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        temp.write(Uy);
        temp.write(theMessage);
        byte[] input = temp.toByteArray();
        byte[] hashOutput = SHA3SHAKE.SHA3(256, input, null);
        BigInteger h = new BigInteger(1, hashOutput).mod(r);

        //Compute z = (k - h * s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        //TODO
        //I now have a keypair? I dont know what to return, h and z.
    }

    //maybe more
    public boolean verify(byte[] theMessage, Edwards.Point V, Edwards theCurve, BigInteger z, BigInteger h)
    {
        BigInteger r = theCurve.r;
        //I dont know what the methods are called yet
        Edwards.Point G = theCurve.gen();

        //Compute U' = z·G + h·V
        Edwards.Point U_prime = G.mul(z).add(V.mul(h));

        //Compute h' = H(U'y || theMessage)
        byte[] UyPrime = U_prime.y.toByteArray();
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        temp.write(UyPrime);
        temp.write(theMessage);
        byte[] input = temp.toByteArray();
        byte[] digest = SHA3SHAKE.SHA3(256, input, null);
        BigInteger hPrime = new BigInteger(1, hashOutput).mod(r);

        return hPrime.equals(h);
    }
}