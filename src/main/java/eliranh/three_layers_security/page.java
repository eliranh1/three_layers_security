package eliranh.three_layers_security;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.UnsupportedAudioFileException;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Image;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextArea;
import com.vaadin.flow.component.upload.Upload;
import com.vaadin.flow.component.upload.receivers.MemoryBuffer;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.StreamResource;

@Route("")
public class page extends VerticalLayout
{
  private InputStream inputStream;
    public page()
    {
        TextArea textArea = new TextArea();
        Button b1 = new Button("aes");
        Button b2 = new Button("chacha");
        MemoryBuffer buffer = new MemoryBuffer();
        Upload upload = new Upload(buffer);
        upload.setMaxFileSize(50*1024*1024); // 16MB
        upload.setAcceptedFileTypes("audio/WAV,image/jpeg");
        b1.addClickListener(e->
        {   
          Notification.show(new String(encrypt_AES(textArea.getValue().getBytes()),StandardCharsets.US_ASCII));
          System.out.println("AES ended"); 
        });
 
        b2.addClickListener(event->
        {
          SecureRandom secureRandom = new SecureRandom();// secured random generation of bytes

          byte[] keyBytes = new byte[32];// 256 bit key
          byte[] nonceBytes = new byte[12];// 96 bit nonce(initialization vector)

          secureRandom.nextBytes(keyBytes);
          secureRandom.nextBytes(nonceBytes);

           int[] key = new int[8];// key as int array
           int[] nonce = new int[3];// nonce as int array

           ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(key);// convertion from byte[] to int[]
           ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(nonce);// convertion from byte[] to int[]

           byte[] cipherText = encrypt_text(key, nonce, textArea.getValue().getBytes());
           Notification.show(new String(cipherText,StandardCharsets.US_ASCII));
           byte[] plainText =  decrypt_text(key, nonce, cipherText);
           Notification.show(new String(plainText,StandardCharsets.US_ASCII));
        });
        upload.addSucceededListener(event->{
          inputStream = buffer.getInputStream();
          if(event.getMIMEType().equals("image/jpeg"))
          {
            Notification.show("image uploaded");
            try {
                byte[] image = hideInJpeg(inputStream, textArea.getValue());
                StreamResource resource = new StreamResource("image", ()->new ByteArrayInputStream(image));
                Image img = new Image(resource,"image");
                add(img);
                extractFromJpeg(image);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
          }
          if(event.getMIMEType().equals("audio/wav"))
          {
            Notification.show("wave uploaded");
            InputStream in = buffer.getInputStream();
            try {
               in = hideInWave(inputStream,textArea.getValue());
            } catch (UnsupportedAudioFileException e1) {
              e1.printStackTrace();
            } catch (IOException e1) {
              e1.printStackTrace();
            }
            File file = new File("C:\\Users\\elira\\OneDrive\\שולחן העבודה\\VSCodeProjects\\demo\\src\\main\\resources\\static\\output.wav");
            try {
              if(in!=null)
              Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e1) {
              e1.printStackTrace(); 
            }
            AudioPlayer audioPlayer = new AudioPlayer();
            audioPlayer.setSource(file.getAbsolutePath());
            add(audioPlayer);
          } 
        });
        add(textArea,b1,b2,upload);
    } 
    private byte[] decrypt_text(int[] key, int[] nonce, byte[] ciphertext)// same process as encryption.
   {
    int counter = 0;
    byte[] decryptedText = new byte[ciphertext.length];
    for (int i = 0; i < ciphertext.length; i += 64) {
      ChaChaState chaChaState = new ChaChaState(key, nonce, counter);
      int[] cipherState = chaChaState.state;
      for (int i2 = 0; i2 < 10; i2++) {
        cipherState = doubleRound(cipherState);
      }
      for (int i3 = 0; i3 < cipherState.length; i3++) {
        cipherState[i3] += chaChaState.state[i3];
      }

      byte[] keyStream = serializeState(cipherState);
      int blockSize = Math.min(64, ciphertext.length - i);

      for (int j = 0; j < blockSize; j++) {
        decryptedText[i + j] = (byte) (ciphertext[i + j] ^ keyStream[j]);
      }
      counter++;
    }
    return decryptedText;
   }
     private byte[] encrypt_text(int[] key, int[] nonce, byte[] plaintext) 
    {
        int counter = 0;// counter initial with zero
        byte[] encryptedText = new byte[plaintext.length];// initialization of encryptedText in plainText size
        for (int i = 0; i < plaintext.length; i += 64)// loop that runs over all the length of plainText for full data
                                                      // encryption
        {
          ChaChaState chaChaState = new ChaChaState(key, nonce, counter);// generate original state
          int[] cipherState = chaChaState.state;// copying the state for the doubleRound actions
          for (int i2 = 0; i2 < 10; i2++)// 20 rounds of quarterRound
          {
            cipherState = doubleRound(cipherState);
          }
          for (int i3 = 0; i3 < cipherState.length; i3++)// addition of the original state
          {
            cipherState[i3] += chaChaState.state[i3];
          }
    
          byte[] keyStream = serializeState(cipherState);// generation of the key stream
          int blockSize = Math.min(64, plaintext.length - i);// determination of the block size that will be XORed
    
          for (int j = 0; j < blockSize; j++)// XOR each plain text's byte with the key stream
          {
            encryptedText[i + j] = (byte) (plaintext[i + j] ^ keyStream[j]);
          }
          counter++;// counter increment
        }
        return encryptedText;
   }
  private byte[] serializeState(int[] state)// convertion of the state to byte[] key stream
  {
    ByteBuffer buffer = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
    for (int i : state) {
      buffer.putInt(i);
    }
    return buffer.array();
  }
  private int[] rowRound(int[] state)// runs the quarter round method order by the rows of the state
  {
    int[] cipher = state;
    cipher = quarterRound(cipher, 0, 1, 2, 3);
    cipher = quarterRound(cipher, 4, 5, 6, 7);
    cipher = quarterRound(cipher, 8, 9, 10, 11);
    cipher = quarterRound(cipher, 12, 13, 14, 15);
    return cipher;
  }

  private int[] columnRound(int[] state)// runs the quarter round method order by the columns of the state
  {
    int[] cipher = state;
    cipher = quarterRound(cipher, 0, 4, 8, 12);
    cipher = quarterRound(cipher, 1, 5, 9, 13);
    cipher = quarterRound(cipher, 2, 6, 10, 14);
    cipher = quarterRound(cipher, 3, 7, 11, 15);
    return cipher;
  }

  private int[] doubleRound(int[] state)// runs rowRound and columnRound methods
  {
    return rowRound(columnRound(state));
  }

  private int[] quarterRound(int[] data, int a, int b, int c, int d)// the core function of the algorithm
  {
    int t = 0;
    t = data[b] ^ (data[a] << 7 | data[a] >>> (32 - 7));
    data[b] = data[a];
    data[a] = t;// bitwise shift left, shift right, XOR, AND.
    t = data[c] ^ (data[b] << 9 | data[b] >>> (32 - 9));
    data[c] = data[b];
    data[b] = t;
    t = data[d] ^ (data[c] << 13 | data[c] >>> (32 - 13));
    data[d] = data[c];
    data[c] = t;
    t = data[a] ^ (data[d] << 18 | data[d] >>> (32 - 18));
    data[a] = data[d];
    data[d] = t;
    return data;
  } 
  private byte[] hideInJpeg(InputStream inputStream,String content) throws IOException 
  {
    // tranfer all image bytes to output stream for multiple use
    ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
    dataStream.write(inputStream.readAllBytes());

    // input stream for search on bytes
    InputStream fullInput = new ByteArrayInputStream(dataStream.toByteArray());
    int marker, markerId, counter = 0;

    while ((marker = fullInput.read()) != -1) 
    {
      counter++;
      if (marker == 0xFF) {
        markerId = fullInput.read();
        counter++;
        if (markerId == 0xFE) // check if com segment exist
        {
          int length = (fullInput.read() << 8) | fullInput.read(); // the length of the com segment
          byte[] firstData = new byte[counter]; // the data of the file before the com segment (includes the markers).

          // reading to the firstData byte array only the first data
          InputStream firstInputStream = new ByteArrayInputStream(dataStream.toByteArray());
          firstInputStream.read(firstData);

          fullInput.skip(length - 2); // skipping the data that in the com segment
          byte[] secondData = fullInput.readAllBytes(); // reading the data that after the com segment
          byte[] secretData = content.getBytes(); // creating byte array of the secret data for injection in the com
                                                  // segment

          length = secretData.length + 2;

          ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream(); // new output stream for the new builded
                                                                             // file
          outputStream2.writeBytes(firstData); // ordered write of the data
          outputStream2.write((length >> 8) & 0xFF);
          outputStream2.write(length & 0xFF);
          outputStream2.writeBytes(secretData);
          outputStream2.writeBytes(secondData);

          byte[] fullData = outputStream2.toByteArray(); // fully builded and injected byte array

          String str = new String(fullData,StandardCharsets.US_ASCII); // debug
          Notification.show(str);
          return fullData;
          // break;
        }
      }
    }
    if (marker == -1) // in case com segment not exist in the file
    {
      counter = 0;

      ByteArrayOutputStream comSegment = new ByteArrayOutputStream();// creating com segment with the text content
      comSegment.write(0xFF);                                          
      comSegment.write(0xFE);                                            
      int length = content.length() + 2;                                   
      comSegment.write((length >> 8) & 0xFF);                            
      comSegment.write(length & 0xFF);                                  
      comSegment.writeBytes(content.getBytes());

      fullInput = new ByteArrayInputStream(dataStream.toByteArray());
      while ((marker = fullInput.read()) != -1)// this loop parsing file and inject the com segment that created
      {
        counter++;
        if (marker == 0xFF) 
        {
          markerId = fullInput.read();
          counter++;
          if (markerId == 0xDB) //check if quantization table is reached
          {
            byte[] firstData = new byte[counter - 2];
            fullInput = new ByteArrayInputStream(dataStream.toByteArray());
            fullInput.read(firstData);

            byte[] secondData = fullInput.readAllBytes();

            ByteArrayOutputStream newFormatStream = new ByteArrayOutputStream();
            newFormatStream.write(firstData);
            newFormatStream.writeBytes(comSegment.toByteArray());
            newFormatStream.write(secondData);

            byte[] fullData = new byte[firstData.length + comSegment.size() + secondData.length];
            fullData = newFormatStream.toByteArray();

            String str = new String(fullData,StandardCharsets.US_ASCII); // debug
            Notification.show(str);
            return fullData;
          }
        }
      }
    }
    return null;
  } 
  private void extractFromJpeg(byte[] data) throws IOException
   {
     InputStream inputStream = new ByteArrayInputStream(data);
     int marker,markerId;
     while((marker = inputStream.read())!=-1)
     {
      if(marker == 0xFF)
      {
        markerId = inputStream.read();
        if(markerId == 0xFE)
        {
         Notification.show("FE found");
         int length = ((inputStream.read()<<8)| inputStream.read());
         byte[] hiddenData = new byte[length - 2];
         inputStream.read(hiddenData);   
         Notification.show(new String(hiddenData,StandardCharsets.US_ASCII)); 
        }
      }
     }
   }  
  private InputStream hideInWave(InputStream inputStream, String content)throws UnsupportedAudioFileException, IOException 
  {
    Notification.show("hide in wave reached");
    AudioInputStream dataStream = AudioSystem.getAudioInputStream(inputStream);
    byte[] audioData = dataStream.readAllBytes();
    System.out.println("audio length: "+audioData.length);
    byte[] messageBytes = content.getBytes();
    StringBuilder binaryMessage = new StringBuilder();

    for (byte b : messageBytes) 
    {
      binaryMessage.append(String.format("%8s", Integer.toBinaryString(b & 0xFF).replace(' ', '0')));
    }
    System.out.println(binaryMessage.toString()+"");

    System.out.println("before: ");
         
    for(int j = 44; j<52;j++)
    {
      byte a = audioData[j];
      System.out.printf("%02x",a);
      System.out.println();
    }
        

    int dataIndex = 0;
    for (int i = 44; i < audioData.length && dataIndex < binaryMessage.length(); i++) 
    {
      audioData[i] &= 0xFE;
      audioData[i] |= Character.getNumericValue(binaryMessage.charAt(dataIndex));
      dataIndex++;
    }
    System.out.println("after: ");
    for(int j = 44; j<52;j++)
    {
      byte a = audioData[j];
      System.out.printf("%02x",a);
      System.out.println();
    }
    return new ByteArrayInputStream(audioData);
  }

  private byte[] encrypt_AES(byte[] plainText) 
  {
    SecureRandom secureRandom = new SecureRandom();
    byte[] key = new byte[32];
    secureRandom.nextBytes(key);

    byte[][] expandedKey = expandKey(key);

    byte[] iv = new byte[16];
    secureRandom.nextBytes(iv);
    byte[] previousBlock = iv;

    int paddingLength = 16 - (plainText.length % 16);
    plainText = Arrays.copyOf(plainText, plainText.length + paddingLength);
    for (int i = 0; i < paddingLength; i++) 
    {
        plainText[plainText.length - 1 - i] = (byte) paddingLength;
    }    

    int numBlocks = plainText.length / 16;
    byte[] cipherText = new byte[plainText.length];

    for (int b = 0; b < numBlocks; b++) 
    {
      byte[] block = Arrays.copyOfRange(plainText, b * 16, (b + 1) * 16);

      // XOR the block with the previous ciphertext block (or IV for the first block)
      for (int i = 0; i < 16; i++) 
      {
        block[i] ^= previousBlock[i];
      }
      
      byte[][] state = generateState(block);

      System.out.println("plainText: ");
      printState(state);
      // Perform 14 rounds of transformations for AES-256
      for (int round = 0; round < 14; round++) 
      {
        state = subBytes(state);
        System.out.println("subBytes ended");
        printState(state);
        state = shiftRows(state);
        System.out.println("shiftRows ended");
        printState(state);
        if (round != 13) // Skip mixColumns on the last round
        {
          state = mixColumns(state);
          System.out.println("mixColumns ended");
          printState(state);
        }
        state = addRoundKey(state, expandedKey, round);
        System.out.println("addRoundKey ended");
        printState(state);
        System.out.println("-------------------round "+round+" is done!-------------------------");
      }

      // Convert the state back to a byte array and store it in the ciphertext
      byte[] encryptedBlock = convertStateToByteArray(state);
      System.arraycopy(encryptedBlock, 0, cipherText, b * 16, 16);

      // Use the encrypted block as the previous ciphertext block for the next round
      previousBlock = encryptedBlock;
    }

    return cipherText;
  }
  private void printState(byte[][] state)
  {
    for (int i = 0; i < state.length; i++) {
      for (int j = 0; j < state[i].length; j++) {
          System.out.printf("%02X ", state[i][j]);
      }
      System.out.println();
  }
  }
  private byte[] convertStateToByteArray(byte[][] state) 
  {
    byte[] block = new byte[16];
    for (int i = 0; i < 4; i++) 
    {
      for (int j = 0; j < 4; j++) 
      {
        block[i * 4 + j] = (byte) state[j][i];
      }
    }
    return block;
  }

  private byte[][] addRoundKey(byte[][] state, byte[][] expandedKey, int round) 
  {
    int[][] roundKey = new int[4][4];

    // Extract the round key from the expanded key
    for (int i = 0; i < 4; i++) 
    {
      for (int j = 0; j < 4; j++) 
      {
        roundKey[i][j] = expandedKey[round * 4 + i][j];
      }
    }
    // Perform the AddRoundKey operation
    for (int i = 0; i < state.length; i++) 
    {
      for (int j = 0; j < state[i].length; j++) 
      {
        state[i][j] ^= roundKey[i][j];
      }
    }
    return state;
  }

  private byte[][] mixColumns(byte[][] state) 
  {
    AesTables tables = new AesTables();
    byte[][] tempState = new byte[4][4];
    for (int c = 0; c < 4; c++) 
    {
      for (int r = 0; r < 4; r++) 
      {
        tempState[r][c] = 0;
        for (int i = 0; i < 4; i++) 
        {
          int low = state[i][c] & 0x0F;
          int high = state[i][c] & 0xF0;
          int num = low^high;
          tempState[r][c] ^= multiply(tables.mixColumnsMatrix[r][i], num);
        }
      }
    }

    for (int r = 0; r < 4; r++) 
    {
      for (int c = 0; c < 4; c++) 
      {
        state[r][c] = tempState[r][c];
      }
    }
    return state;
  }

  private int multiply(int a, int b) 
  {
    //System.out.println("matrix: "+a);
    //System.out.println("state num: "+b);
    int result = 0;
    while (a != 0 && b != 0) 
    {
      if ((b & 1) != 0) 
      {
        result ^= a;
      }
      boolean highBitSet = (a & 0x80) != 0;
      a <<= 1;
      if (highBitSet) 
      {
        a ^= 0x1b; // This is the primitive polynomial x^8 + x^4 + x^3 + x + 1
      }
      b >>= 1;
    }
    
    return result & 0xFF;
  }

  private byte[][] shiftRows(byte[][] state) 
  {
    for (int row = 1; row < 4; row++) 
    {
      byte[] tempRow = new byte[4];
      for (int col = 0; col < 4; col++) 
      {
        tempRow[col] = state[row][(col + row) % 4];
      }
      state[row] = tempRow;
    }
    return state;
  }

  private byte[][] subBytes(byte[][] state) 
  {
    AesTables tables = new AesTables();
    for (int row = 0; row < 4; row++) 
    {
      
      for (int col = 0; col < 4; col++) 
      { 
        int sBoxRow = (state[row][col] & 0xF0) >> 4; // Get the higher 4 bits
        int sBoxCol = state[row][col] & 0x0F; // Get the lower 4 bits
        state[row][col] = (byte)tables.SBOX[sBoxRow][sBoxCol];
      }
    }
    return state;
  }

  private byte[][] generateState(byte[] plainText) 
  {
    byte[][] state = new byte[4][4];
    for (int i = 0; i < plainText.length; i++) 
    {
      state[i % 4][i / 4] = plainText[i];
    }

    return state;
  }

  private static byte[][] expandKey(byte[] key) 
  {
    byte[][] roundKeys = new byte[60][4]; // 15 round keys for AES-256
    byte[] temp = new byte[4];

    // Copy the original key to the round keys array
    for (int i = 0; i < 8; i++) 
    {
      System.arraycopy(key, i * 4, roundKeys[i], 0, 4);
    }

    for (int i = 8; i < 60; i++) 
    {
      System.arraycopy(roundKeys[i - 1], 0, temp, 0, 4);

      // Key schedule core
      if (i % 8 == 0) 
      {
        temp = scheduleCore(temp, i / 8);
      }

      for (int j = 0; j < 4; j++) 
      {
        roundKeys[i][j] = (byte) (roundKeys[i - 8][j] ^ temp[j]);
      }
    }

    return roundKeys;
  }

  private static byte[] scheduleCore(byte[] in, int i) 
  {
    // Rotate
    byte t = in[0];
    System.arraycopy(in, 1, in, 0, 3);
    in[3] = t;

    AesTables tables = new AesTables();
    // SubBytes
    for (int j = 0; j < 4; j++) 
    {
      int high = (in[j] & 0xF0) >> 4;
      int low = in[j] & 0x0F;
      in[j] = (byte) tables.SBOX[high][low];
    }

    // Rcon
    in[0] ^= tables.RCON[i];

    return in;
  }
}
