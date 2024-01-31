package eliranh.three_layers_security;


public class ChaChaState 
{
    public int[] state = new int[16];
    public int[] key;
    public int[] nonce;
    public int counter;
    public int[] constants = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
 
    public ChaChaState(int[] key, int[] nonce, int counter)
    {
     this.key = key;
     this.nonce = nonce;
     this.counter = counter;
     System.arraycopy(constants, 0, state, 0, 4);
     System.arraycopy(key, 0, state, 4, 8);
     state[12] = counter;
     System.arraycopy(nonce, 0, state, 13, 3);
    } 
}
