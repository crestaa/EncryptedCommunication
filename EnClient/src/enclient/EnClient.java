/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enclient;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


/**
 *
 * @author Gabriele
 */
public class EnClient {
    public static final int PORT = 1050; // porta al di fuori del range 1-1024 !
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, Exception {
        Socket socket=null;
        BufferedReader fromServer=null, keyboard=null;
        PrintWriter toServer=null;
        
        // creazione stream di input da tastiera
        keyboard = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("EnServer IP address or hostname: ");
        String userInput=keyboard.readLine();
        InetAddress addr = InetAddress.getByName(userInput);
        
        try {
            //INIZIALIZZAZIONE CONNESSIONE
            socket = new Socket(addr, PORT);
            System.out.println("---- EnClient started ----");
            System.out.println("Client Socket: "+ socket);
            InputStreamReader isr = new InputStreamReader( socket.getInputStream());
            fromServer = new BufferedReader(isr);
            OutputStreamWriter osw = new OutputStreamWriter( socket.getOutputStream());
            BufferedWriter bw = new BufferedWriter(osw);
            toServer = new PrintWriter(bw, true);
            
            
            //HANDSHAKE E SCAMBIO CHIAVI PUBBLICHE
            RSA rsa = new RSA();
            //invio la mia chiave pubblica
            toServer.println(Base64.getEncoder().encodeToString(rsa.getPubKey().getEncoded()));
	    
            //ricevo la chiave pubblica del server
	    X509EncodedKeySpec  keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(fromServer.readLine()));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");	  
	    PublicKey k = keyFactory.generatePublic(keySpec);
            
            
            
            // ciclo di lettura da tastiera, invio al server e stampa risposta
            while (true){
                System.out.print("Write something to send: ");
                userInput = keyboard.readLine();
                
                if (userInput.equals("END")) break;
                
                //invio messaggio al server
                String enc = rsa.encrypt(userInput,k);
                System.out.println("\nI'm sending "+userInput+"\nWhich corresponds to " + enc);
                toServer.println(enc);
                
                //ricezione risposta dal server
                String recv = fromServer.readLine();
                System.out.println("I've received "+recv+"\nWhich corresponds to " + rsa.decrypt(recv)+"\n\n");
            }
        }
        catch (UnknownHostException e) {
            System.err.println("Don’t know about host "+ addr);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn’t get I/O for the connection to: " + addr);
            System.exit(1);
        }
        System.out.println("EchoClient: closing...");
        toServer.close();
        fromServer.close();
        keyboard.close();
        socket.close();
    }
    
}
