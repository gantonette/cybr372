package part5;

public class vPNG{
    private long seed;
    public vPNG(long seed){
        this.seed = seed;
    }
    public byte next(){
        seed = (seed * 6364136223846793005L + 1442695040888963407L) & 0xFFFFFFFF;
        return (byte) (seed % 256);
    }
}
