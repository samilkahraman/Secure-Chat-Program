package Chat;
//
//  CertificateAuthorityThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them

import java.net.*;
import java.io.*;
import javax.swing.JTextArea;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class CertificateAuthorityThread extends Thread {

    private CertificateAuthority CA;
    private ServerSocket serverSocket;
    private int portNum;
    private String hostName;
    private JTextArea outputArea;

    CertificateAuthorityThread(CertificateAuthority ca) {

        super( "CertificateAuthorityThread" );
        CA = ca;
        portNum = ca.getPortNumber();
        outputArea = ca.getOutputArea();
        serverSocket = null;

        try {

            InetAddress serverAddress = InetAddress.getByName( null );
            hostName = serverAddress.getHostName();

        } catch (UnknownHostException e) {
            hostName = "0.0.0.0";
        }
    }


    //  Accept connections and service them one at a time
    public void run() {

        try {

            serverSocket = new ServerSocket( portNum );

            outputArea.append( "CA waiting on " + hostName + " port " + portNum );

            while (true) try {
                Socket socket = serverSocket.accept();

                OutputStream outStream = socket.getOutputStream();
                InputStream inStream = socket.getInputStream();
                ObjectOutputStream out = new ObjectOutputStream(outStream);
                ObjectInputStream in = new ObjectInputStream(inStream);
                /*
                * Got the connection, now do what is required
                * First complete the handshake
                * Determine who sent it
                * verify the username and password hash
                * issue a certificate signed with the private key
                *
                * */

                // Receive registration request
                RegistrationRequest requestPacket = (RegistrationRequest) in.readObject();

                if (requestPacket != null) {

                    // Check whether the registration is done before or not with this username looking packet
                    // existance
                    outputArea.append( "\nRegistration request for user < " + requestPacket.username + ">" );

                    // Check registration request packet's certificate in CA's keystore
                    Certificate existingCertificate = CA.keyStore.getCertificate( requestPacket.username );
                    X509Certificate certificate = null;

                    // If there is not a certificate for this user, generate a new certificate for the user's public
                    // key and return it to the user and store the username-certificate pair in its keystore to
                    // remember that the user was registered or not in forthcoming requests.
                    if (existingCertificate == null) {
                        certificate = X509CertificateGenerator.generateCertificate( "CN=" + requestPacket.username +
                                        ", O=zencilerTrust, C=TR",
                                CA.keyPair.getPrivate(), requestPacket.publicKey, 90, "SHA256withRSA" );

                        //save the certificate in CA's keystore for remember that user
                        CA.keyStore.setCertificateEntry( requestPacket.username, certificate );
                        FileOutputStream keyStoreStream = new FileOutputStream("C:\\Users\\Şamil\\Documents\\NetBeansProjects\\JavaApplication3\\src\\Chat\\keyStore_CA" );
                        CA.keyStore.store( keyStoreStream, CA.privateKeyPassword );

                        outputArea.append( "\nRegistration completed." );
                    }

                    // send the certificate to the user
                    out.writeObject( certificate );
                }
            } catch (Exception e) {

                System.out.println( "\nConnection error: " + e.getMessage() );
                e.printStackTrace();
            }
        } catch (Exception e)

        {
            System.out.println( "CA thread error: " + e.getMessage() );
            e.printStackTrace();
        }

    }
}