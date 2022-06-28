/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enserver;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
/**
 *
 * @author Gabriele
 */
public class EnServer {
    public static final int PORT = 1050; // porta al di fuori del range 1-1024 !
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)  throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("---- EnServer started ----");
        System.out.println("Server Socket: " + serverSocket);
        Socket clientSocket=null;
        BufferedReader fromClient=null;
        PrintWriter toClient=null;
        try {
            // bloccante finchè non avviene una connessione
            clientSocket = serverSocket.accept();
            System.out.println("Connection accepted: "+ clientSocket);
            // creazione stream di input da clientSocket
            InputStreamReader isr = new InputStreamReader(clientSocket.getInputStream());
            fromClient = new BufferedReader(isr);
            // creazione stream di output su clientSocket
            OutputStreamWriter osw = new OutputStreamWriter(clientSocket.getOutputStream());
            BufferedWriter bw = new BufferedWriter(osw);
            toClient = new PrintWriter(bw, true);
            
            //HANDSHAKE E SCAMBIO CHIAVI PUBBLICHE
            RSA rsa = new RSA();
            
            //ricevo la chiave pubblica del client
            X509EncodedKeySpec  keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(fromClient.readLine()));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");	  
	    PublicKey k = keyFactory.generatePublic(keySpec);
            
            //invio la mia chiave pubblica
            toClient.println(Base64.getEncoder().encodeToString(rsa.getPubKey().getEncoded()));
            
            
            //ciclo di ricezione dal client e invio di risposta
            while (true) {
                String recv = fromClient.readLine();
                String dec = rsa.decrypt(recv);
                if (recv.equals("END")) break;
                
                System.out.println("\nI've received "+recv+"\nWhich corresponds to " + dec);
                String enc = rsa.encrypt(dec, k);
                System.out.println("I'm sending "+enc+"\nWhich corresponds to " + dec+"\n\n");
                toClient.println(enc);
            }
        }
        catch (IOException e) {
            System.err.println("Accept failed");
            System.exit(1);
        }
        // chiusura di stream e socket
        System.out.println("EchoServer: closing...");
        toClient.close();
        fromClient.close();
        clientSocket.close();
        serverSocket.close();
    }
    
}
