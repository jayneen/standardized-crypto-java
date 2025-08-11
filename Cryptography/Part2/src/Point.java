import java.math.BigInteger;

public class Point {
    private final BigInteger x;
    private final BigInteger y;
    private final boolean isZero;

    private static final BigInteger P = BigInteger.valueOf(2).pow(256).subtract(BigInteger.valueOf(189));
    private static final BigInteger D = BigInteger.valueOf(15343);

    /**
     * Create a copy of the neutral element on this curve.
     */
    public Point() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
        this.isZero = true;
    }

    /**
     * Create a point from its coordinates (assuming
     * these coordinates really define a point on the curve).
     *
     * @param x the x-coordinate of the desired point
     * @param y the y-coordinate of the desired point
     */
    private Point(BigInteger x, BigInteger y) {
        this.x = x.mod(P);
        this.y = y.mod(P);
        this.isZero = this.x.equals(BigInteger.ZERO) && this.y.equals(BigInteger.ONE);
    }

    /**
     * Determine if this point is the neutral element O on the curve.
     *
     * @return true iff this point is O
     */
    public boolean isZero() {
        return this.isZero;
    }

    /**
     * Determine if a given point P stands for
     * the same point on the curve as this.
     *
     * @param P a point (presumably on the same curve as this)
     * @return true iff P stands for the same point as this
     */
    public boolean equals(Point P) {
        if (this.isZero && P.isZero) {
            return true;
        }
        return this.x.equals(P.x) && this.y.equals(P.y);
    }

    /**
     * Given a point P = (x, y) on the curve,
     * return its opposite -P = (-x, y).
     *
     * @return -P
     */
    public Point negate() {
        if (isZero) {
            return this;
        }
        return new Point(x.negate().mod(P), y);
    }

    /**
     * Add two given points on the curve, this and P.
     *
     * @param Q a point on the curve
     * @return this + P
     */
    public Point add(Point Q) {
        if (this.isZero)
            return Q;
        if (Q.isZero)
            return this;

        BigInteger x1 = this.x;
        BigInteger y1 = this.y;
        BigInteger x2 = Q.x;
        BigInteger y2 = Q.y;

        BigInteger x1x2 = x1.multiply(x2).mod(P);
        BigInteger y1y2 = y1.multiply(y2).mod(P);
        BigInteger x1y2 = x1.multiply(y2).mod(P);
        BigInteger y1x2 = y1.multiply(x2).mod(P);
        BigInteger dxxyy = D.multiply(x1x2).multiply(y1y2).mod(P);

        BigInteger numeratorX = x1y2.add(y1x2).mod(P);
        BigInteger denominatorX = BigInteger.ONE.add(dxxyy).mod(P);

        BigInteger numeratorY = y1y2.subtract(x1x2).mod(P);
        BigInteger denominatorY = BigInteger.ONE.subtract(dxxyy).mod(P);

        BigInteger invDenX = denominatorX.modInverse(P);
        BigInteger invDenY = denominatorY.modInverse(P);

        BigInteger x3 = numeratorX.multiply(invDenX).mod(P);
        BigInteger y3 = numeratorY.multiply(invDenY).mod(P);

        return new Point(x3, y3);
    }

    /**
     * Multiply a point P = (x, y) on the curve by a scalar m.
     *
     * @param m a scalar factor (an integer mod the curve order)
     * @return m*P
     */
    public Point mul(BigInteger m) {
        Point result = new Point();
        Point base = this;

        while (m.signum() > 0) {
            if (m.testBit(0)) {
                result = result.add(base);
            }
            base = base.add(base);
            m = m.shiftRight(1);
        }

        return result;
    }

    /**
     * Display a human-readable representation of this point.
     *
     * @return a string of form "(x, y)" where x and y are
     *         the coordinates of this point
     */
    public String toString() {
        return "(" + x.toString() + ", " + y.toString() + ")";
    }
}
