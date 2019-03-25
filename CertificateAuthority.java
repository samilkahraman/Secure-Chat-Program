package Chat;

//
//  CertificateAuthority.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//  Editted by : Yunus Can Basesme <ybasesme@etu.edu.tr> & Mehmet Samil Kahraman<msamilkahraman.etu.edu.tr>

//  AWT/Swing

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;


public class CertificateAuthority {

    public static final int SUCCESS = 0;
    public static final int KEYSTORE_FILE_NOT_FOUND = 1;
    public static final int ERROR = 4;

    // GUI PART
    CertificateAuthorityLoginPanel _panel;
    CertificateAuthorityActivityPanel _activityPanel;
    CardLayout _layout;
    JFrame _appFrame;

    //  Port number to listen on
    private int _portNum;
    // The filename of the keystore
    String keystoreFileName;
    char[] privateKeyPassword;
    KeyStore keyStore;
    //key pair(public, private)
    KeyPair keyPair;

    private CertificateAuthority() {
        _panel = null;
        _activityPanel = null;
        _layout = null;
        _appFrame = null;

        try {
            initialize();
        } catch (Exception e) {
            System.out.println( "CA error: " + e.getMessage() );
            e.printStackTrace();
        }
        _layout.show( _appFrame.getContentPane(), "CAPanel" );
    }

    private void initialize() {
        _appFrame = new JFrame("Certificate Authority");
        _layout = new CardLayout();

        _appFrame.getContentPane().setLayout(_layout);
        _panel = new CertificateAuthorityLoginPanel(this);
        _appFrame.getContentPane().add(_panel, "CAPanel");

        _activityPanel = new CertificateAuthorityActivityPanel(this);
        _appFrame.getContentPane().add(_activityPanel, "ActivityPanel");

        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        } );
    }

    private void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);
    }

    public void quit() {
        try {
            System.out.println("quit called.");
        } catch (Exception err) {
            System.out.println("CertificateAuthority error: " + err.getMessage());
            err.printStackTrace();
        }
        System.exit( 0 );
    }

    public int startup(String _ksFileName,
                       char[] _privateKeyPass,
                       int _caPort) throws IOException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException {

        //  Port number to listen on
        _portNum = _caPort;
        keystoreFileName = _ksFileName;
        privateKeyPassword = _privateKeyPass;

        // Load CAs keystore
        FileInputStream keyStoreStream = new FileInputStream( "C:\\Users\\Şamil\\Documents\\NetBeansProjects\\JavaApplication3\\src\\Chat\\keyStore_CA");
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(keyStoreStream, privateKeyPassword);

        // From keyStore_CA, get CAs certificate and its keypair contains public and private key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("ca", privateKeyPassword);
        // We get certificate here
        Certificate certificate = keyStore.getCertificate("ca");
        // We get key pair here
        keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
        _layout.show( _appFrame.getContentPane(), "ActivityPanel" );
        CertificateAuthorityThread _thread = new CertificateAuthorityThread(this);
        _thread.start();
        return CertificateAuthority.SUCCESS;
    }

    public int get_portNum() {

        return _portNum;
    }

    public JTextArea getOutputArea() {

        return _activityPanel.getOutputArea();
    }

    //  main
    //
    //  Construct the CA panel, read in the passwords and give the
    //  control back
    public static void main(String[] args) {

        CertificateAuthority ca = new CertificateAuthority();
        ca.run();
    }

    int getPortNumber() {
        return _portNum;
    }
}