import java.net.*;
import java.io.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.security.cert.*;
import java.nio.file.Files;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Paths;
import java.security.interfaces.*;

import org.apache.commons.codec.binary.*;


public class server implements Runnable {

    private byte[] chavePartilhada;
    private SecureRandom random;

    public static String sha256(String text) { 
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        String encodedHash = Hex.encodeHexString(hash);      
        return encodedHash;

        } catch (Exception e) {
            return null;
        }
        
    }

    public String encrypt(byte[] chavePartilhada, String initVector, String message) {
        try{ 
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(chavePartilhada, 0, 16, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(message.getBytes());

        String textoCifradoString = Hex.encodeHexString(encrypted);
  
        return textoCifradoString;
        
        } catch (Exception e){}
    return null;
    }

    public String decrypt(byte[] chavePartilhada, String initVector, String encrypted) {
        try{
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(chavePartilhada, 0, 16, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] decodedBytes = Hex.decodeHex(encrypted.toCharArray());
        byte[] original = cipher.doFinal(decodedBytes);
        String textoLimpo = new String(original);

        return textoLimpo;

        } catch (Exception e) {}
    return null;
    }

    public String hmacAuth(String key, String data) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            String MACString = Hex.encodeHexString(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
            
            return MACString;

        } catch (Exception e) {
            return null;
        }
       

    }

    public String assinar(String mensagem, PrivateKey chavePrivAssinatura) {
        try {
            byte[] mensagemBytes = mensagem.getBytes();
            Signature assinatura = Signature.getInstance("SHA256withRSA"); 
            assinatura.initSign(chavePrivAssinatura);
            assinatura.update(mensagemBytes);
            byte[] assinaturaBytes = assinatura.sign();
            String assinaturaString = Hex.encodeHexString(assinaturaBytes);
            return assinaturaString;
        } catch (Exception e) {
            return null;
        }    
    }

    public byte[] inicioAcordoDH(BufferedReader entrada, PrintWriter saida, String initVector){

        try {
            // Instanceacoes
            KeyPairGenerator geradorParChaves = KeyPairGenerator.getInstance("DiffieHellman");
            KeyAgreement acordoChaves = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory chaveFactory = KeyFactory.getInstance("DiffieHellman");


            // p e g dados no enunciado - TODO implementar gerador de primos e enviar para o cliente
            BigInteger primoMod = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
            BigInteger gerador = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");


            DHParameterSpec dhPS = new DHParameterSpec(primoMod, gerador);
            geradorParChaves.initialize(dhPS, this.random);
            KeyPair parChaves = geradorParChaves.generateKeyPair();

            
            // envia chave publica DH do servidor para o cliente
            String dhChaveServEnviadaEncoded = Hex.encodeHexString(parChaves.getPublic().getEncoded());
            saida.println(dhChaveServEnviadaEncoded);
            saida.flush();

            // recebe chave publica DH do cliente para o servidor - inicializa objeto PK_Client com a chave recebida
            String dhChaveClientRecebidaEncoded = entrada.readLine();
            byte[] bytesChavePubClient = Hex.decodeHex(dhChaveClientRecebidaEncoded.toCharArray());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytesChavePubClient);
            PublicKey chavePubClient = chaveFactory.generatePublic(ks);

            // finalizacao do acordo - computacao de chave partilhada
            acordoChaves.init(parChaves.getPrivate());
            acordoChaves.doPhase(chavePubClient, true);
            this.chavePartilhada = acordoChaves.generateSecret();


            // le a chave publica do certificado e guarda num objeto PublicKey
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream ("../certs/servCertificado.pem");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey chaveAssinaturaPubServ = cer.getPublicKey();
            
            

            // le a chave privada de assinatura do servidor e guarda num objeto PrivateKey
            byte[] chaveAssinaturaPrivadaBytes = Files.readAllBytes(Paths.get("../certs/servidorPrivKeyPKCS8")); 
            PKCS8EncodedKeySpec chavePrivadaSpec = new PKCS8EncodedKeySpec(chaveAssinaturaPrivadaBytes);
            KeyFactory chaveFactoryRSA = KeyFactory.getInstance("RSA");
            PrivateKey chaveAssinaturaPrivServ = chaveFactoryRSA.generatePrivate(chavePrivadaSpec);

            //assinar o par ordenado e cifra com a chave Partilhada
            String assinatura=assinar(dhChaveServEnviadaEncoded+dhChaveClientRecebidaEncoded,chaveAssinaturaPrivServ);
            String assinaturaCifrada = encrypt(chavePartilhada,initVector,assinatura);
            
            //envia o objeto assinatura e a chave Publica DH cifrados ao cliente (order matters according to wiki)
            saida.println(assinaturaCifrada);
            saida.flush();


            System.out.println("O cliente " + threadNumber + " realizou com sucesso o protocolo de ligacao (DiffieHelman com assinatura one-way - TLS like)");
		    return this.chavePartilhada;    
            
        } catch (Exception e) {
            return null;
        }
        
    }
   
    
    public String recSeguro(BufferedReader entrada, byte[] chavePartilhada, String initVector, int contador, String hmacKey) throws Exception {
        String criptogramaComMac = entrada.readLine();
        String macGerado = criptogramaComMac.substring(0,64);
        String textoCifrado = criptogramaComMac.substring(64,criptogramaComMac.length());

        if (macGerado.equals(hmacAuth(hmacKey+contador,textoCifrado))) {
            String textoRecuperado = decrypt(chavePartilhada,initVector,textoCifrado);
            contador++;
            return textoRecuperado;
        } else {
            System.out.println("Erro de MAC  - abortar comunicacoes");
            return null;
        }
    }

    public void envioSeguro(String textoLimpo, PrintWriter saida, byte[] chavePartilhada, int contador, String initVector, String hmacKey) throws Exception {
        String textoCifrado = encrypt(chavePartilhada,initVector,textoLimpo);
        String macGerado = hmacAuth(hmacKey+contador, textoCifrado);
        saida.println(macGerado+textoCifrado);
        saida.flush();
        contador++;
    }

    public void verificarLogin(PrintWriter saida,byte[] chavePartilhada,int contador,String initVector,String hmacKey, BufferedReader entrada) throws Exception {
        Boolean approved = false;
        do {
        String passwordHash = recSeguro(entrada,chavePartilhada,initVector,contador,hmacKey);
        if (passwordHash.equals("6133cd131055d985d2466d0567da043bd708026c19487032a779efd062bdc327")) {
            envioSeguro("granted",saida,chavePartilhada,contador,initVector,hmacKey);
            approved = true;
            System.out.println("O cliente "+threadNumber+ " autenticou-se com sucesso");
        } else {
            envioSeguro("denied",saida,chavePartilhada,contador,initVector,hmacKey);
        }
    } while (approved==false);

    }

    public void recMenu(PrintWriter saida,byte[] chavePartilhada,int contador,String initVector,String hmacKey, BufferedReader entrada) throws Exception {
        String choice = recSeguro(entrada, chavePartilhada, initVector, contador, hmacKey);
        switch (choice) {
            case "1":
                String consultaDeSaldo = "----- Consulta de Saldo -----\nFabio Freitas | Saldo: 200,00€";
                envioSeguro(consultaDeSaldo, saida, chavePartilhada, contador, initVector, hmacKey);
                System.out.println("O cliente "+threadNumber+" consultou o seu saldo com sucesso");
        }
    }

    //incompleto
    


    public Socket s;
    public static int threadNumber = 0;
    public server(Socket s){
        this.s=s;
    }
        public static void main (String arg[]) throws UnknownHostException, IOException
        {
            
                //Startup de servidor

                ServerSocket server=new ServerSocket(2000);
                System.out.print("\033[H\033[2J");
                System.out.println("Servidor iniciado. A espera de conexoes.");

                //Criacao de thread para cada nova conexao
                while (true) {
                Socket s=server.accept();
                server j = new server(s);
                Thread t = new Thread(j);

                //Thread.Start chama o método run():
                t.start();
                threadNumber++;

                
                }
                
            }

        public void run(){
            try {
                //Definicao de buffers
                BufferedReader entrada=null;
                entrada = new BufferedReader(new InputStreamReader(s.getInputStream()));

                PrintWriter saida = null;
                saida = new PrintWriter(s.getOutputStream());

                Scanner x=null;
                x = new Scanner(this.s.getInputStream());

                String initVector = "RandomInitVector";

                // DiffieHelman Protocol
                chavePartilhada=inicioAcordoDH(entrada,saida,initVector);

                String hashKeyGenerator = sha256(Hex.encodeHexString(chavePartilhada));         // Passo a chavePartilhada por uma funcao de hash para nao usar a mesma chave na cifra e mac
                String hmacKey = hashKeyGenerator.substring(0,hashKeyGenerator.length()/2);     // Passo a chavePartilhada por uma funcao de hash para nao usar a mesma chave na cifra e mac
                int contador = 0;                                                               // Contador para MAC

                

                try {
                    verificarLogin(saida,chavePartilhada,contador,initVector,hmacKey,entrada);

                    recMenu(saida, chavePartilhada, contador, initVector, hmacKey, entrada);
                } catch (Exception e) {}
                
                
                //Close dos objetos
                this.s.close();
                System.out.println("O cliente " + threadNumber + " fechou a ligacao com o servidor");

                
            } catch (IOException e) {};   
        }
            
    }