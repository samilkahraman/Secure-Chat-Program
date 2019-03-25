
package Chat;

//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.

//  AWT/Swing


import java.awt.*;
import java.awt.event.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;


public class ChatClient {

    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;

    private CardLayout _cardLayout;
    private JFrame _appFrame;
    private ChatRoomPanel _chatRoomPanel;

    ObjectOutputStream out = null;
    ObjectInputStream in = null;

    private String loginName;

    private ChatClientThread _thread;
    private Socket _socket = null;


    SecretKey roomKey;

    boolean exists = true;


    private ChatClient() {

        loginName = null;

        try {
            initComponents();
        } catch (Exception e) {
            System.out.println( "ChatClient error: " + e.getMessage() );
            e.printStackTrace();
        }

        _cardLayout.show( _appFrame.getContentPane(), "Login" );

    }

    private void run() {
        _appFrame.pack();
        _appFrame.setVisible( true );

    }


    public static void main(String[] args) {

        ChatClient app = new ChatClient();
        app.run();
    }


    private void initComponents() {

        _appFrame = new JFrame( "Chat Room" );
        _cardLayout = new CardLayout();
        _appFrame.getContentPane().setLayout( _cardLayout );
        ChatLoginPanel _chatLoginPanel = new ChatLoginPanel( this );
        _chatRoomPanel = new ChatRoomPanel( this );
        _appFrame.getContentPane().add( _chatLoginPanel, "Login" );
        _appFrame.getContentPane().add( _chatRoomPanel, "ChatRoom" );
        _appFrame.addWindowListener( new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        } );
    }

    public void quit() {

        try {
            exists = false;
            _socket.shutdownOutput();
            _socket.close();
            _thread.join();


        } catch (Exception err) {
            System.out.println( "ChatClient error: " + err.getMessage() );
            err.printStackTrace();
        }
        System.exit( 0 );
    }


    public int connect(String userName,
                       String roomName,
                       String roomType,
                       String keyStoreName, char[] keyStorePassword,
                       String caHost, int caPort,
                       String serverHost, int serverPort) {

        try {

            loginName = userName;


            System.out.println( "\n\nConnecting to CA" );

            // User's keystore is being brought
            System.out.println("User's keystore is being brought");
            FileInputStream inputStream = new FileInputStream( "C:\\Users\\Şamil\\Documents\\NetBeansProjects\\JavaApplication3\\src\\Chat\\keyStore_Client" );
            KeyStore userKeyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
            userKeyStore.load( inputStream, keyStorePassword );
            PublicKey CAPublicKey = userKeyStore.getCertificate( "ca" ).getPublicKey();

            // Check whether there exist a certificate with this username or not
            System.out.println( "Checking whether there exist a certificate with this username or not" );
            PrivateKey RSAPrivateKey;
            Certificate userCertificate;
            if (!userKeyStore.isCertificateEntry( loginName )) {

                // Check users certificate with username, if does not exists
                System.out.println( "User's certificate does not exists." );

                // Receive user's public key to make new registration request
                RSAPrivateKey = (PrivateKey) userKeyStore.getKey( "client", keyStorePassword );
                userCertificate = userKeyStore.getCertificate( "client" );
                PublicKey RSAPublicKey = userCertificate.getPublicKey();
                System.out.println( "User's public key has received" );

                // Connect to CA for new registration request
                Socket ca_socket = new Socket( caHost, caPort );
                OutputStream outStream = ca_socket.getOutputStream();
                InputStream inStream = ca_socket.getInputStream();
                out = new ObjectOutputStream( outStream );
                in = new ObjectInputStream( inStream );

                System.out.println( "Connected to CA for registration request." );

                // Send CA, username and RSA public key of the user
                out.writeObject( new RegistrationRequest( loginName, RSAPublicKey ) );
                System.out.println( "\tsent CA username and RSA public key." );

                try {
                    // receive certificate from CA
                    userCertificate = (X509Certificate) in.readObject();
                    System.out.println( "\treceived certificate from CA." );

                    // verify CA
                    userCertificate.verify( CAPublicKey );
                    System.out.println( "\tverified CA." );


                } catch (ClassCastException caste) {
                    return CONNECTION_REFUSED;
                } catch (Exception e) {
                    return BAD_HOST;
                }

                out.close();
                in.close();


                // Save the certificate in user's keystore
                userKeyStore.setCertificateEntry( loginName, userCertificate );
                FileOutputStream keyStoreStream = new FileOutputStream("C:\\Users\\Şamil\\Documents\\NetBeansProjects\\JavaApplication3\\src\\Chat\\keyStore_Client" );
                userKeyStore.store( keyStoreStream, keyStorePassword );
                System.out.println( "Saved the certificate in user's keystore." );

            } else { //if user has registred before and has a certificate

                System.out.println( "User's certificate exists." );
                // Check users certificate with username, if  exists
                // Received RSA private key and certificate from keystore
                RSAPrivateKey = (PrivateKey) userKeyStore.getKey( "client", keyStorePassword );
                userCertificate = userKeyStore.getCertificate( loginName );
                System.out.println( "Received user's RSA private key and certificate from keystore." );

            }

            // Connecting to Server ...
            System.out.println( "\n\nConnecting to Server ..." );

            _socket = new Socket( serverHost, serverPort );
            OutputStream outStream = _socket.getOutputStream();
            InputStream inStream = _socket.getInputStream();
            out = new ObjectOutputStream( outStream );
            in = new ObjectInputStream( inStream );

            System.out.println( "Connected to server." );

            // Receiving server's packet
            System.out.println( " Receiving server's packet..." );
            ServerPacket serverPacket = (ServerPacket) in.readObject();

            DHPublicKey DHServerPublicKey = serverPacket.getDHServerKey();

            // Getting server's certificate
            System.out.println( "\tGetting server's certificate..." );
            Certificate serverCert = serverPacket.getServerCertificate();

            System.out.println( "Verifying server's certificate" );
            serverCert.verify( CAPublicKey );
            if (!serverPacket.verify()) {
                return BAD_HOST;
            }

            // Server key exchange
            System.out.println( " Server key exchange completed." );

            // Generate DH key part
            System.out.println( " Generating DH key part..." );
            KeyPairGenerator keyPairGenerator;
            keyPairGenerator = KeyPairGenerator.getInstance( "DiffieHellman" );
            // parameters

            DHPublicKeySpec DHServerPublicKeyPart = serverPacket.getDHServerPart();
            DHParameterSpec dhParameterSpec = new DHParameterSpec( DHServerPublicKeyPart.getP(), DHServerPublicKeyPart.getG() );
            keyPairGenerator.initialize( dhParameterSpec );
            KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();

            // Create and send client packet
            System.out.println( "Sending client packet..." );
            Certificate serverCertificate = serverPacket.getServerCertificate();
            ClientPacket clientPacket = new ClientPacket( userCertificate, serverCertificate, generateKeyPair.getPublic(), RSAPrivateKey, serverPacket );
            out.writeObject( clientPacket );

            // Sent client packet.
            System.out.println( "Sent client packet." );

            // Calculating shared secret...
            System.out.println( "Calculating shared secret..." );
            KeyAgreement keyAgreement = KeyAgreement.getInstance( "DH" );
            keyAgreement.init( generateKeyPair.getPrivate() );
            keyAgreement.doPhase( DHServerPublicKey, true );
            SecretKey secretKey = keyAgreement.generateSecret( "AES" );

            // Key exchange completed.
            System.out.println( "Key exchange completed." );

            // Initializing symmetric ciphers...
            System.out.println( "\nInitializing symmetric ciphers..." );
            Cipher encryptCipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
            Cipher decryptCipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
            byte[] ivParameterBytes = "guaicnjqwvgfashsh".getBytes();
            IvParameterSpec ivParameterSpec = new IvParameterSpec( ivParameterBytes, 0, 16 );
            encryptCipher.init( Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec );
            decryptCipher.init( Cipher.DECRYPT_MODE, secretKey, ivParameterSpec );

            // Sending join room request...
            System.out.println( "Sending join room request..." );
            out.writeObject( new SealedObject( roomName, encryptCipher ) );
            out.writeObject( new SealedObject( roomType, encryptCipher ) );

            // Join room request sent.
            System.out.println( "Join room request sent." );

            // Receiving joining room requests respond
            System.out.println( " Receiving joining room requests respond..." );
            SealedObject roomRespond = (SealedObject) in.readObject();
            roomKey = (SecretKey) roomRespond.getObject( decryptCipher );

            if (roomKey == null) {
                System.out.println( "Joining room failed." );
                return CONNECTION_REFUSED;
            }

            System.out.println( "Joined room." );

            _cardLayout.show( _appFrame.getContentPane(), "ChatRoom" );

            _thread = new ChatClientThread( this );
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println( "Don't know about the serverHost: " + serverHost );

        } catch (IOException e) {

            System.err.println( "Couldn't get I/O for the connection to the serverHost: " + serverHost );
            System.out.println( "ChatClient error: " + e.getMessage() );
            e.printStackTrace();


        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println( "ChatClient err: " + e.getMessage() );
            e.printStackTrace();
        }

        return ERROR;

    }


    public void sendMessage(String msg) {
        try {
            msg = loginName + "> " + msg;
            Message message = new Message( msg, roomKey );
            out.writeObject( message );
        } catch (Exception e) {
            System.out.println( "ChatClient err: " + e.getMessage() );
            e.printStackTrace();
        }
    }

    public Socket getSocket() {
        return _socket;
    }

    public JTextArea getOutputArea() {

        return _chatRoomPanel.getOutputArea();
    }

}